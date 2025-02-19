/*
Copyright 2020 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package grant

import (
	"context"
	"fmt"
	"strings"

	"github.com/lib/pq"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	xpcontroller "github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/logging"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	"github.com/crossplane-contrib/provider-sql/apis/postgresql/v1alpha1"
	"github.com/crossplane-contrib/provider-sql/pkg/clients"
	"github.com/crossplane-contrib/provider-sql/pkg/clients/postgresql"
	"github.com/crossplane-contrib/provider-sql/pkg/clients/xsql"
)

const (
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errNoSecretRef  = "ProviderConfig does not reference a credentials Secret"
	errGetSecret    = "cannot get credentials Secret"

	errNotGrant     = "managed resource is not a Grant custom resource"
	errSelectGrant  = "cannot select grant"
	errCreateGrant  = "cannot create grant"
	errRevokeGrant  = "cannot revoke grant"
	errNoRole       = "role not passed or could not be resolved"
	errNoDatabase   = "database not passed or could not be resolved"
	errNoPrivileges = "privileges not passed"
	errUnknownGrant = "cannot identify grant type based on passed params"

	errInvalidParams = "invalid parameters for grant type %s"

	errMemberOfWithDatabaseOrPrivileges = "cannot set privileges or database in the same grant as memberOf"

	maxConcurrency = 5

	errDatabaseDoesNotExist = "database does not exist"

	defaultPostgresDB = "postgres" // Add this constant
)

// Setup adds a controller that reconciles Grant managed resources.
func Setup(mgr ctrl.Manager, o xpcontroller.Options) error {
	name := managed.ControllerName(v1alpha1.GrantGroupKind)

	t := resource.NewProviderConfigUsageTracker(mgr.GetClient(), &v1alpha1.ProviderConfigUsage{})
	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.GrantGroupVersionKind),
		managed.WithExternalConnecter(&connector{
			kube: mgr.GetClient(), 
			usage: t,
			logger: o.Logger,
			newDB: postgresql.New,
		}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithPollInterval(o.PollInterval),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))))

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&v1alpha1.Grant{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: maxConcurrency,
		}).
		Complete(r)
}

type connector struct {
	kube   client.Client
	usage  resource.Tracker
	logger logging.Logger
	newDB  func(creds map[string][]byte, database string, sslmode string) xsql.DB
}

func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.Grant)
	if !ok {
		return nil, errors.New(errNotGrant)
	}

	if err := c.usage.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	// ProviderConfigReference could theoretically be nil, but in practice the
	// DefaultProviderConfig initializer will set it before we get here.
	pc := &v1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: cr.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetPC)
	}

	// We don't need to check the credentials source because we currently only
	// support one source (PostgreSQLConnectionSecret), which is required and
	// enforced by the ProviderConfig schema.
	ref := pc.Spec.Credentials.ConnectionSecretRef
	if ref == nil {
		return nil, errors.New(errNoSecretRef)
	}

	s := &corev1.Secret{}
	if err := c.kube.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, s); err != nil {
		return nil, errors.Wrap(err, errGetSecret)
	}

	// Use postgres database if target database doesn't exist
	targetDB := pc.Spec.DefaultDatabase
	if cr.Spec.ForProvider.Database != nil {
		// Try to connect to target database first
		testDb := c.newDB(s.Data, *cr.Spec.ForProvider.Database, clients.ToString(pc.Spec.SSLMode))
		err := testDb.Exec(ctx, xsql.Query{String: "SELECT 1"})
		if err != nil && isDatabaseNotExistError(err) {
			c.logger.Debug("[CONNECT] Target database does not exist, connecting to postgres database", 
                "database", *cr.Spec.ForProvider.Database,
                "error", err)
			targetDB = defaultPostgresDB
		} else if err != nil {
			c.logger.Debug("[CONNECT] Failed to connect to database", 
                "database", *cr.Spec.ForProvider.Database,
                "error", err)
			return nil, errors.Wrap(err, "cannot connect to database")
		} else {
			targetDB = *cr.Spec.ForProvider.Database
		}
	}

	return &external{
		db:     c.newDB(s.Data, targetDB, clients.ToString(pc.Spec.SSLMode)),
		kube:   c.kube,
		logger: c.logger,
	}, nil
}

type external struct {
	db     xsql.DB
	kube   client.Client
	logger logging.Logger // Add logger field
}

type grantType string

const (
	roleMember      grantType = "ROLE_MEMBER"
	roleDatabase    grantType = "ROLE_DATABASE"
	roleSchema      grantType = "ROLE_SCHEMA"
	roleTables      grantType = "ROLE_TABLES"
	roleSequences   grantType = "ROLE_SEQUENCES"
	roleFunctions   grantType = "ROLE_FUNCTIONS"
	roleLargeObjects grantType = "ROLE_LARGE_OBJECTS"
)

func identifyGrantType(gp v1alpha1.GrantParameters) (grantType, error) {
    pc := len(gp.Privileges)

    // If memberOf is specified, this is ROLE_MEMBER
    if gp.MemberOfRef != nil || gp.MemberOfSelector != nil || gp.MemberOf != nil {
        if gp.Database != nil || pc > 0 {
            return "", errors.New(errMemberOfWithDatabaseOrPrivileges)
        }
        return roleMember, nil
    }

    // Check for onTables, onSequences, etc first
    if gp.OnTables {
        return roleTables, nil
    }
    if gp.OnSequences {
        return roleSequences, nil
    }
    if gp.OnFunctions {
        return roleFunctions, nil
    }
    if gp.OnLargeObjects {
        return roleLargeObjects, nil
    }

    // Check for schema-level grants
    if gp.Schema != nil {
        return roleSchema, nil
    }
    
    // For database grants, we need both database and privileges
    if gp.Database == nil {
        // Only return error if we're not handling a memberOf grant
        if pc > 0 {
            return "", errors.New(errNoDatabase)
        }
    }

    if pc < 1 {
        return "", errors.New(errNoPrivileges)
    }

    return roleDatabase, nil
}

func selectGrantQuery(gp v1alpha1.GrantParameters, q *xsql.Query) error {
	gt, err := identifyGrantType(gp)
	if err != nil {
		return err
	}

	switch gt {
	case roleMember:
		ao := gp.WithOption != nil && *gp.WithOption == v1alpha1.GrantOptionAdmin

		// Always returns a row with a true or false value
		// A simpler query would use ::regrol to cast the
		// roleid and member oids to their role names, but
		// if this is used with a nonexistent role name it will
		// throw an error rather than return false.
		q.String = "SELECT EXISTS(SELECT 1 FROM pg_auth_members m " +
			"INNER JOIN pg_roles mo ON m.roleid = mo.oid " +
			"INNER JOIN pg_roles r ON m.member = r.oid " +
			"WHERE r.rolname=$1 AND mo.rolname=$2 AND " +
			"m.admin_option = $3)"

		q.Parameters = []interface{}{
			gp.Role,
			gp.MemberOf,
			ao,
		}
		return nil
	case roleDatabase:
		gro := gp.WithOption != nil && *gp.WithOption == v1alpha1.GrantOptionGrant

		ep := gp.Privileges.ExpandPrivileges()
		sp := ep.ToStringSlice()
		// Join grantee. Filter by database name and grantee name.
		// Finally, perform a permission comparison against expected
		// permissions.
		q.String = "SELECT EXISTS(SELECT 1 " +
			"FROM pg_database db, " +
			"aclexplode(datacl) as acl " +
			"INNER JOIN pg_roles s ON acl.grantee = s.oid " +
			// Filter by database, role and grantable setting
			"WHERE db.datname=$1 " +
			"AND s.rolname=$2 " +
			"AND acl.is_grantable=$3 " +
			"GROUP BY db.datname, s.rolname, acl.is_grantable " +
			// Check privileges match. Convoluted right-hand-side is necessary to
			// ensure identical sort order of the input permissions.
			"HAVING array_agg(acl.privilege_type ORDER BY privilege_type ASC) " +
			"= (SELECT array(SELECT unnest($4::text[]) as perms ORDER BY perms ASC)))"

		q.Parameters = []interface{}{
			gp.Database,
			gp.Role,
			gro,
			pq.Array(sp),
		}
		return nil
	case roleTables, roleSequences, roleFunctions:		
		var objType string
		switch gt {
			case roleTables:
				objType = "r"  // regular table
			case roleSequences:
				objType = "S"  // sequence
			case roleFunctions:
				objType = "f"  // function
			}

		if gp.DefaultPrivileges != nil && *gp.DefaultPrivileges && gp.ForRole != nil {
			// Query to check default privileges
			q.String = `
				SELECT EXISTS(
					SELECT 1 
					FROM pg_default_acl a
					JOIN pg_namespace n ON n.oid = a.defaclnamespace
					JOIN pg_roles r ON r.oid = a.defaclrole
					WHERE n.nspname = $1 
					AND r.rolname = $2
					AND a.defaclobjtype = $3
					AND EXISTS (
						SELECT 1
						FROM aclexplode(a.defaclacl) acl
						JOIN pg_roles g ON g.oid = acl.grantee
						WHERE g.rolname = $4
						AND array_agg(acl.privilege_type ORDER BY acl.privilege_type) @> $5::text[]
					)
				)`

			q.Parameters = []interface{}{
				gp.Schema,
				gp.ForRole,
				objType,
				gp.Role,
				pq.Array(gp.Privileges.ToStringSlice()),
			}
			return nil
		}

		 // Modified query to handle cases with no objects
		q.String = `
			WITH object_permissions AS (
				SELECT cls.oid,
					COALESCE(array_agg(acl.privilege_type ORDER BY acl.privilege_type), ARRAY[]::text[]) as privileges
				FROM pg_class cls
				JOIN pg_namespace ns ON cls.relnamespace = ns.oid
				LEFT JOIN aclexplode(cls.relacl) acl ON true
				LEFT JOIN pg_roles r ON acl.grantee = r.oid AND r.rolname = $2
				WHERE ns.nspname = $1
				AND cls.relkind = $3
				GROUP BY cls.oid
			)
			SELECT CASE 
				WHEN COUNT(*) = 0 THEN true -- No objects exist, consider it synchronized
				WHEN COUNT(*) = COUNT(CASE WHEN privileges @> $4::text[] THEN 1 END) THEN true -- All objects have required permissions
				ELSE false -- Some objects exist but don't have required permissions
			END
			FROM object_permissions`

		q.Parameters = []interface{}{
			gp.Schema,
			gp.Role,
			objType,
			pq.Array(gp.Privileges.ToStringSlice()),
		}
		return nil
	case roleLargeObjects:
		// Modified query to use pg_roles instead of pg_authid
		q.String = `
			WITH object_permissions AS (
				SELECT pglm.oid,
					COALESCE(array_agg(acl.privilege_type ORDER BY acl.privilege_type), ARRAY[]::text[]) as privileges
				FROM pg_largeobject_metadata pglm 
				INNER JOIN pg_roles pga ON pglm.lomowner = pga.oid
				LEFT JOIN aclexplode(pglm.lomacl) acl ON true
				LEFT JOIN pg_roles r ON acl.grantee = r.oid AND r.rolname = $2
				WHERE pga.rolname = $1
				GROUP BY pglm.oid
			)
			SELECT CASE 
				WHEN COUNT(*) = 0 THEN true -- No large objects exist, consider it synchronized
				WHEN COUNT(*) = COUNT(CASE WHEN privileges @> $3::text[] THEN 1 END) THEN true
				ELSE false -- Some objects exist but don't have required permissions
			END
			FROM object_permissions`

		q.Parameters = []interface{}{
			gp.LargeObjectOwner,
			gp.Role,
			pq.Array(gp.Privileges.ToStringSlice()),
		}
		return nil
	case roleSchema:
        // Query to check if schema permissions exist
        q.String = `
            WITH schema_permissions AS (
                SELECT n.nspname,
                    COALESCE(array_agg(acl.privilege_type ORDER BY acl.privilege_type), ARRAY[]::text[]) as privileges
                FROM pg_namespace n
                LEFT JOIN aclexplode(n.nspacl) acl ON true
                LEFT JOIN pg_roles r ON acl.grantee = r.oid AND r.rolname = $2
                WHERE n.nspname = $1
                GROUP BY n.nspname
            )
            SELECT CASE 
                WHEN COUNT(*) = 0 THEN false
                WHEN COUNT(*) = COUNT(CASE WHEN privileges @> $3::text[] THEN 1 END) THEN true
                ELSE false
            END
            FROM schema_permissions`

        q.Parameters = []interface{}{
            gp.Schema,
            gp.Role,
            pq.Array(gp.Privileges.ToStringSlice()),
        }
        return nil
	}
	return errors.New(errUnknownGrant)
}

func withOption(option *v1alpha1.GrantOption) string {
	if option != nil {
		return fmt.Sprintf("WITH %s OPTION", string(*option))
	}
	return ""
}

func createGrantQueries(gp v1alpha1.GrantParameters, ql *[]xsql.Query) error { // nolint: gocyclo
	gt, err := identifyGrantType(gp)
	if err != nil {
		return err
	}

	ro := pq.QuoteIdentifier(*gp.Role)

	switch gt {
	case roleMember:
		if gp.MemberOf == nil || gp.Role == nil {
			return errors.Errorf(errInvalidParams, roleMember)
		}

		mo := pq.QuoteIdentifier(*gp.MemberOf)

		*ql = append(*ql,
			xsql.Query{String: fmt.Sprintf("REVOKE %s FROM %s", mo, ro)},
			xsql.Query{String: fmt.Sprintf("GRANT %s TO %s %s", mo, ro,
				withOption(gp.WithOption),
			)},
		)
		return nil
	case roleDatabase:
		if gp.Database == nil || gp.Role == nil || len(gp.Privileges) < 1 {
			return errors.Errorf(errInvalidParams, roleDatabase)
		}

		db := pq.QuoteIdentifier(*gp.Database)
		sp := strings.Join(gp.Privileges.ToStringSlice(), ",")
ileges != nil && *gp.DefaultPrivileges && gp.ForRole != nil {
		*ql = append(*ql,
			// REVOKE ANY MATCHING EXISTING PERMISSIONS= append(*ql,
			xsql.Query{String: fmt.Sprintf("REVOKE %s ON DATABASE %s FROM %s",ery{String: fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s GRANT %s ON TABLES TO %s %s",
				sp,rRole,
				db,chema,
				ro,
			)},,
					withOption(gp.WithOption),
				)},RANT REQUESTED PERMISSIONS
			)ntf("GRANT %s ON DATABASE %s TO %s %s",
			return nil,
		}	db,
		
		*ql = append(*ql,				withOption(gp.WithOption),
			xsql.Query{String: fmt.Sprintf("REVOKE %s ON ALL TABLES IN SCHEMA %s FROM %s",
				sp,
				schema,okePublicOnDb {
				ro,	*ql = append(*ql,
			)},
			xsql.Query{String: fmt.Sprintf("GRANT %s ON ALL TABLES IN SCHEMA %s TO %s %s",L ON DATABASE %s FROM PUBLIC",
				sp,
				schema,
				ro,
				withOption(gp.WithOption),
			)}, nil
		)leTables:
		return nilges.ToStringSlice(), ",")
a := pq.QuoteIdentifier(*gp.Schema)
	case roleSequences:
		sp := strings.Join(gp.Privileges.ToStringSlice(), ",")d(*ql,
		schema := pq.QuoteIdentifier(*gp.Schema)xsql.Query{String: fmt.Sprintf("REVOKE %s ON ALL TABLES IN SCHEMA %s FROM %s",
				sp,
		if gp.DefaultPrivileges != nil && *gp.DefaultPrivileges && gp.ForRole != nil {
			forRole := pq.QuoteIdentifier(*gp.ForRole)
			*ql = append(*ql,
				xsql.Query{String: fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s GRANT %s ON SEQUENCES TO %s %s",ry{String: fmt.Sprintf("GRANT %s ON ALL TABLES IN SCHEMA %s TO %s %s",
					forRole,
					schema,hema,
					sp,
					ro,hOption(gp.WithOption),
					withOption(gp.WithOption),
				)},
			)
			return nil
		}se roleSequences:
		ngs.Join(gp.Privileges.ToStringSlice(), ",")
		*ql = append(*ql,		schema := pq.QuoteIdentifier(*gp.Schema)
			xsql.Query{String: fmt.Sprintf("REVOKE %s ON ALL SEQUENCES IN SCHEMA %s FROM %s",
				sp,s && gp.ForRole != nil {
				schema,le)
				ro,	*ql = append(*ql,
			)},ng: fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s GRANT %s ON SEQUENCES TO %s %s",
			xsql.Query{String: fmt.Sprintf("GRANT %s ON ALL SEQUENCES IN SCHEMA %s TO %s %s",
				sp,hema,
				schema,
				ro,,
				withOption(gp.WithOption),ithOption(gp.WithOption),
			)},
		)
		return nilil

	case roleFunctions:
		sp := strings.Join(gp.Privileges.ToStringSlice(), ",")= append(*ql,
		schema := pq.QuoteIdentifier(*gp.Schema)xsql.Query{String: fmt.Sprintf("REVOKE %s ON ALL SEQUENCES IN SCHEMA %s FROM %s",
		
		*ql = append(*ql,
			xsql.Query{String: fmt.Sprintf("REVOKE %s ON ALL FUNCTIONS IN SCHEMA %s FROM %s",
				sp,
				schema,uery{String: fmt.Sprintf("GRANT %s ON ALL SEQUENCES IN SCHEMA %s TO %s %s",
				ro,				sp,
			)},
			xsql.Query{String: fmt.Sprintf("GRANT %s ON ALL FUNCTIONS IN SCHEMA %s TO %s %s",
				sp,
				schema,			)},
				ro,
				withOption(gp.WithOption),
			)},
		)
		return nil
	case roleLargeObjects:
        if gp.Role == nil || gp.LargeObjectOwner == nil {
            return errors.Errorf(errInvalidParams, roleLargeObjects)
        }%s",

        // First query finds all large objects owned by specified owner
        sp := strings.Join(gp.Privileges.ToStringSlice(), ",")
        ro := pq.QuoteIdentifier(*gp.Role)
s ON ALL FUNCTIONS IN SCHEMA %s TO %s %s",
        *ql = append(*ql,
            xsql.Query{String: fmt.Sprintf(a,
                "DO $$ DECLARE r record; "+
                "BEGIN "+.WithOption),
                "FOR r IN SELECT DISTINCT(pglm.oid) as oid FROM pg_largeobject_metadata pglm "+
                "INNER JOIN pg_roles pga ON pglm.lomowner = pga.oid "+ // Changed from pg_authid to pg_roles
                "WHERE pga.rolname = '%s' "+nil
                "LOOP "+	case roleLargeObjects:
                "EXECUTE 'GRANT %s ON LARGE OBJECT ' || r.oid || ' TO %s %s'; "+
                "END LOOP; END $$;",s, roleLargeObjects)
                *gp.LargeObjectOwner,        }
                sp,
                ro,
                withOption(gp.WithOption),gs.Join(gp.Privileges.ToStringSlice(), ",")
            )},dentifier(*gp.Role)
        )
        return nilppend(*ql,
	case roleSchema:
        if gp.Schema == nil || gp.Role == nil || len(gp.Privileges) < 1 { $$ DECLARE r record; "+
            return errors.Errorf(errInvalidParams, roleSchema)"+
        }R r IN SELECT DISTINCT(pglm.oid) as oid FROM pg_largeobject_metadata pglm "+
N pglm.lomowner = pga.oid "+ // Changed from pg_authid to pg_roles
        sp := strings.Join(gp.Privileges.ToStringSlice(), ",") "WHERE pga.rolname = '%s' "+
        schema := pq.QuoteIdentifier(*gp.Schema)       "LOOP "+
XECUTE 'GRANT %s ON LARGE OBJECT ' || r.oid || ' TO %s %s'; "+
        *ql = append(*ql,              "END LOOP; END $$;",
            xsql.Query{String: fmt.Sprintf("REVOKE %s ON SCHEMA %s FROM %s",r,
                sp,               sp,
                schema,                ro,
                ro,
            )},
            xsql.Query{String: fmt.Sprintf("GRANT %s ON SCHEMA %s TO %s %s",
                sp,
                schema,
                ro,   if gp.Schema == nil || gp.Role == nil || len(gp.Privileges) < 1 {
                withOption(gp.WithOption),            return errors.Errorf(errInvalidParams, roleSchema)
            )},
        )
        return niltrings.Join(gp.Privileges.ToStringSlice(), ",")
	}.QuoteIdentifier(*gp.Schema)
	return errors.New(errUnknownGrant)
}
l.Query{String: fmt.Sprintf("REVOKE %s ON SCHEMA %s FROM %s",
// Delete the duplicate deleteGrantQuery function and keep only this version       sp,
func deleteGrantQuery(gp v1alpha1.GrantParameters, q *xsql.Query) error {hema,
    gt, err := identifyGrantType(gp)
    if err != nil {
        return errA %s TO %s %s",
    }
 schema,
    ro := pq.QuoteIdentifier(*gp.Role)       ro,
thOption(gp.WithOption),
    switch gt {
    case roleMember:
        q.String = fmt.Sprintf("REVOKE %s FROM %s",return nil
            pq.QuoteIdentifier(*gp.MemberOf),
            ro,Grant)
        )
        return nil
    case roleDatabase:e the duplicate deleteGrantQuery function and keep only this version
        q.String = fmt.Sprintf("REVOKE %s ON DATABASE %s FROM %s",s, q *xsql.Query) error {
            strings.Join(gp.Privileges.ToStringSlice(), ","),err := identifyGrantType(gp)
            pq.QuoteIdentifier(*gp.Database),
            ro,
        )
        return nil
    case roleTables, roleSequences, roleFunctions:r(*gp.Role)
        sp := strings.Join(gp.Privileges.ToStringSlice(), ",")
        
        // Make sure we have a schema
        if gp.Schema == nil {.String = fmt.Sprintf("REVOKE %s FROM %s",
            return errors.New("schema is required")            pq.QuoteIdentifier(*gp.MemberOf),
        }
        
        schema := pq.QuoteIdentifier(*gp.Schema)nil
        e:
        var objType stringfmt.Sprintf("REVOKE %s ON DATABASE %s FROM %s",
        switch gt {ings.Join(gp.Privileges.ToStringSlice(), ","),
        case roleTables:   pq.QuoteIdentifier(*gp.Database),
            objType = "TABLES"
        case roleSequences:
            objType = "SEQUENCES"
        case roleFunctions:
            objType = "FUNCTIONS"p := strings.Join(gp.Privileges.ToStringSlice(), ",")
        }

        // First revoke on existing objects
        q.String = fmt.Sprintf("REVOKE %s ON ALL %s IN SCHEMA %s FROM %s",            return errors.New("schema is required")
            sp,
            objType,
            schema,q.QuoteIdentifier(*gp.Schema)
            ro,
        )ar objType string
        return nil{
    case roleSchema:   case roleTables:
        if gp.Schema == nil {
            return errors.New("schema is required")       case roleSequences:
        }            objType = "SEQUENCES"
        
        sp := strings.Join(gp.Privileges.ToStringSlice(), ",")
        schema := pq.QuoteIdentifier(*gp.Schema)

        q.String = fmt.Sprintf("REVOKE %s ON SCHEMA %s FROM %s",
            sp,      q.String = fmt.Sprintf("REVOKE %s ON ALL %s IN SCHEMA %s FROM %s",
            schema,            sp,
            ro,
        )
        return nil          ro,
    }        )
    return errors.New(errUnknownGrant)
}

// Modified Observe method with clean SQL logginga is required")
func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.Grant)
	if (!ok) {
		return managed.ExternalObservation{}, errors.New(errNotGrant)    schema := pq.QuoteIdentifier(*gp.Schema)
	}
     q.String = fmt.Sprintf("REVOKE %s ON SCHEMA %s FROM %s",
	if cr.Spec.ForProvider.Role == nil {
		return managed.ExternalObservation{}, errors.New(errNoRole)
	}
     )
	// Switch to the correct database if specified      return nil
	if cr.Spec.ForProvider.Database != nil {    }
		if err := c.db.Exec(ctx, xsql.Query{String: fmt.Sprintf("SELECT set_config('search_path', 'public', false); SELECT pg_catalog.set_config('statement_timeout', '0', false)")}); err != nil {nknownGrant)
			if isDatabaseNotExistError(err) {
				// If database doesn't exist, treat as resource doesn't exist
				c.logger.Debug("[OBSERVE] Database does not exist, considering grant as non-existent")
				return managed.ExternalObservation{ResourceExists: false}, nilext, mg resource.Managed) (managed.ExternalObservation, error) {
			}r, ok := mg.(*v1alpha1.Grant)
			return managed.ExternalObservation{}, errors.Wrap(err, "failed to reset search_path")	if (!ok) {
		}rrors.New(errNotGrant)
		switchQuery := fmt.Sprintf("SET SESSION AUTHORIZATION DEFAULT; SELECT pg_catalog.set_config('statement_timeout', '0', false); SET search_path TO public")
		if err := c.db.Exec(ctx, xsql.Query{String: switchQuery}); err != nil {
			return managed.ExternalObservation{}, errors.Wrap(err, "failed to reset session")rovider.Role == nil {
		}oRole)
	}

	gp := cr.Spec.ForProvider/ Switch to the correct database if specified
	var query xsql.Query	if cr.Spec.ForProvider.Database != nil {
	if err := selectGrantQuery(gp, &query); err != nil {.db.Exec(ctx, xsql.Query{String: fmt.Sprintf("SELECT set_config('search_path', 'public', false); SELECT pg_catalog.set_config('statement_timeout', '0', false)")}); err != nil {
		c.logger.Debug("[ERROR][OBSERVE] Failed to build query", "error", err)
		return managed.ExternalObservation{}, errt
	}		c.logger.Debug("[OBSERVE] Database does not exist, considering grant as non-existent")
				return managed.ExternalObservation{ResourceExists: false}, nil
	// Log before execution with cleaned SQL
	c.logger.Debug("[OBSERVE] Executing SQL", "query", cleanSQLForLog(query.String), "parameters", query.Parameters)			return managed.ExternalObservation{}, errors.Wrap(err, "failed to reset search_path")

	exists := false		switchQuery := fmt.Sprintf("SET SESSION AUTHORIZATION DEFAULT; SELECT pg_catalog.set_config('statement_timeout', '0', false); SET search_path TO public")
	if err := c.db.Scan(ctx, query, &exists); err != nil {y{String: switchQuery}); err != nil {
		c.logger.Debug("[OBSERVE] Failed to execute SQL", "error", err)ation{}, errors.Wrap(err, "failed to reset session")
		return managed.ExternalObservation{}, errors.Wrap(err, errSelectGrant)
	}

	if !exists {gp := cr.Spec.ForProvider
		c.logger.Debug("[WARN][OBSERVE] Executed SQL: Grant does not exist")	var query xsql.Query
		return managed.ExternalObservation{ResourceExists: false}, nilnil {
	}
ation{}, err
	c.logger.Debug("[OBSERVE] Executed SQL OK. Grant exists")

	cr.SetConditions(xpv1.Available())/ Log before execution with cleaned SQL
	c.logger.Debug("[OBSERVE] Executing SQL", "query", cleanSQLForLog(query.String), "parameters", query.Parameters)
	return managed.ExternalObservation{
		ResourceExists:          true,
		ResourceUpToDate:        true,
		ResourceLateInitialized: false,
	}, nileturn managed.ExternalObservation{}, errors.Wrap(err, errSelectGrant)
}

// Modified Create method with clean SQL logging
func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {.logger.Debug("[WARN][OBSERVE] Executed SQL: Grant does not exist")
	cr, ok := mg.(*v1alpha1.Grant)return managed.ExternalObservation{ResourceExists: false}, nil
	if !ok {	}
		return managed.ExternalCreation{}, errors.New(errNotGrant)
	}	c.logger.Debug("[OBSERVE] Executed SQL OK. Grant exists")

	// Switch to the correct database if specified	cr.SetConditions(xpv1.Available())
	if cr.Spec.ForProvider.Database != nil {
		if err := c.db.Exec(ctx, xsql.Query{String: fmt.Sprintf("SELECT set_config('search_path', 'public', false); SELECT pg_catalog.set_config('statement_timeout', '0', false)")}); err != nil {
			return managed.ExternalCreation{}, errors.Wrap(err, "failed to reset search_path")
		}ResourceUpToDate:        true,
		switchQuery := fmt.Sprintf("SET SESSION AUTHORIZATION DEFAULT; SELECT pg_catalog.set_config('statement_timeout', '0', false); SET search_path TO public")		ResourceLateInitialized: false,
		if err := c.db.Exec(ctx, xsql.Query{String: switchQuery}); err != nil {
			return managed.ExternalCreation{}, errors.Wrap(err, "failed to reset session")
		}
	} Modified Create method with clean SQL logging
func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	var queries []xsql.Query

	cr.SetConditions(xpv1.Creating())

	if err := createGrantQueries(cr.Spec.ForProvider, &queries); err != nil {
		c.logger.Debug("[ERROR][CREATE] Failed to build queries", "error", err)fied
		return managed.ExternalCreation{}, errors.Wrap(err, errCreateGrant)	if cr.Spec.ForProvider.Database != nil {
	}tring: fmt.Sprintf("SELECT set_config('search_path', 'public', false); SELECT pg_catalog.set_config('statement_timeout', '0', false)")}); err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "failed to reset search_path")
	// Log before execution with cleaned SQL		}
	for _, q := range queries {ZATION DEFAULT; SELECT pg_catalog.set_config('statement_timeout', '0', false); SET search_path TO public")
		c.logger.Debug("[CREATE] Executing SQL", "query", cleanSQLForLog(q.String), "parameters", q.Parameters)
	}{}, errors.Wrap(err, "failed to reset session")

	if err := c.db.ExecTx(ctx, queries); err != nil {
		c.logger.Debug("[ERROR][CREATE] Failed to execute SQL", "error", err)
		return managed.ExternalCreation{}, errors.Wrap(err, errCreateGrant)	var queries []xsql.Query
	}
)
	c.logger.Debug("[CREATE] Executed SQL OK")
	if err := createGrantQueries(cr.Spec.ForProvider, &queries); err != nil {
	return managed.ExternalCreation{}, nil
}Wrap(err, errCreateGrant)

// Fix the Delete method to not handle finalizers
func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
    cr, ok := mg.(*v1alpha1.Grant) {
    if (!ok) {bug("[CREATE] Executing SQL", "query", cleanSQLForLog(q.String), "parameters", q.Parameters)
        return errors.New(errNotGrant)
    }

    c.logger.Debug("[DELETE] Starting deletion", 
        "resource", cr.GetName(),rap(err, errCreateGrant)
        "deletionTimestamp", cr.GetDeletionTimestamp())

    // If we need to switch database but it doesn't exist, consider the grant already deletedug("[CREATE] Executed SQL OK")
    if cr.Spec.ForProvider.Database != nil {
        if err := c.db.Exec(ctx, xsql.Query{String: fmt.Sprintf("SELECT set_config('search_path', 'public', false); SELECT pg_catalog.set_config('statement_timeout', '0', false)")}); err != nil {anaged.ExternalCreation{}, nil
            if isDatabaseNotExistError(err) {
                c.logger.Debug("[DELETE] Database does not exist, considering grant already deleted")
                return nil to not handle finalizers
            } {
            return errors.Wrap(err, "failed to reset search_path")
        }
        switchQuery := fmt.Sprintf("SET SESSION AUTHORIZATION DEFAULT; SELECT pg_catalog.set_config('statement_timeout', '0', false); SET search_path TO public")   return errors.New(errNotGrant)
        if err := c.db.Exec(ctx, xsql.Query{String: switchQuery}); err != nil {    }
            if isDatabaseNotExistError(err) {
                c.logger.Debug("[DELETE] Database does not exist, considering grant already deleted")    c.logger.Debug("[DELETE] Starting deletion", 
                return nil
            }
            return errors.Wrap(err, "failed to reset session")
        }/ If we need to switch database but it doesn't exist, consider the grant already deleted
    }    if cr.Spec.ForProvider.Database != nil {
intf("SELECT set_config('search_path', 'public', false); SELECT pg_catalog.set_config('statement_timeout', '0', false)")}); err != nil {
    var query xsql.Query isDatabaseNotExistError(err) {
    if err := deleteGrantQuery(cr.Spec.ForProvider, &query); err != nil {               c.logger.Debug("[DELETE] Database does not exist, considering grant already deleted")
        c.logger.Debug("[ERROR][DELETE] Failed to build query", "error", err)                return nil
        return errors.Wrap(err, errRevokeGrant)
    }r, "failed to reset search_path")

    c.logger.Debug("[DELETE] Executing REVOKE", "query", cleanSQLForLog(query.String), "parameters", query.Parameters)FAULT; SELECT pg_catalog.set_config('statement_timeout', '0', false); SET search_path TO public")
   if err := c.db.Exec(ctx, xsql.Query{String: switchQuery}); err != nil {
    if err := c.db.Exec(ctx, query); err != nil {            if isDatabaseNotExistError(err) {
        c.logger.Debug("[ERROR][DELETE] Failed to execute SQL", "error", err)")
        return errors.Wrap(err, errRevokeGrant)
    }
        return errors.Wrap(err, "failed to reset session")
    c.logger.Debug("[DELETE] Successfully executed REVOKE")
    return nil   }
}
    var query xsql.Query
func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {ery(cr.Spec.ForProvider, &query); err != nil {
    _, ok := mg.(*v1alpha1.Grant)iled to build query", "error", err)
    if (!ok) {
        return managed.ExternalUpdate{}, errors.New(errNotGrant)
    }
c.logger.Debug("[DELETE] Executing REVOKE", "query", cleanSQLForLog(query.String), "parameters", query.Parameters)
    // Update is a no-op, as permissions are fully revoked and then granted in the Create function,
    // inside a transaction.!= nil {
    c.logger.Debug("[UPDATE] No-op, permissions are handled in Create")e SQL", "error", err)
       return errors.Wrap(err, errRevokeGrant)
    return managed.ExternalUpdate{}, nil}
}
   c.logger.Debug("[DELETE] Successfully executed REVOKE")
    return nil
// Add this helper function
func cleanSQLForLog(query string) string {
    // Replace all newlines and tabs with a single spaceUpdate(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
    cleaned := strings.ReplaceAll(query, "\n", " ")alpha1.Grant)
    cleaned = strings.ReplaceAll(cleaned, "\t", " ")f (!ok) {
    ternalUpdate{}, errors.New(errNotGrant)
    // Replace multiple spaces with a single space
    for strings.Contains(cleaned, "  ") {
        cleaned = strings.ReplaceAll(cleaned, "  ", " ")   // Update is a no-op, as permissions are fully revoked and then granted in the Create function,
    }    // inside a transaction.














}           (strings.Contains(errMsg, "does not exist") && strings.Contains(errMsg, "database"))    return strings.Contains(errMsg, errDatabaseDoesNotExist) ||     errMsg := err.Error()    }        return false    if err == nil {func isDatabaseNotExistError(err error) bool {// Add this helper function}    return strings.TrimSpace(cleaned)        c.logger.Debug("[UPDATE] No-op, permissions are handled in Create")
    
    return managed.ExternalUpdate{}, nil
}


// Add this helper function
func cleanSQLForLog(query string) string {
    // Replace all newlines and tabs with a single space
    cleaned := strings.ReplaceAll(query, "\n", " ")
    cleaned = strings.ReplaceAll(cleaned, "\t", " ")
    
    // Replace multiple spaces with a single space
    for strings.Contains(cleaned, "  ") {
        cleaned = strings.ReplaceAll(cleaned, "  ", " ")
    }
    
    return strings.TrimSpace(cleaned)
}

// Add this helper function
func isDatabaseNotExistError(err error) bool {
    if err == nil {
        return false
    }
    errMsg := err.Error()
    return strings.Contains(errMsg, errDatabaseDoesNotExist) || 
           (strings.Contains(errMsg, "does not exist") && strings.Contains(errMsg, "database"))
}
