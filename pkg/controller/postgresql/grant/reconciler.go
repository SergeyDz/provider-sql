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
	return &external{
		db:     c.newDB(s.Data, pc.Spec.DefaultDatabase, clients.ToString(pc.Spec.SSLMode)),
		kube:   c.kube,
		logger: c.logger, // Pass logger from connector
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
	// NOTE: If any of these are set, even if the lookup by ref or selector fails,
	// then this is still a roleMember grant type.
	if gp.MemberOfRef != nil || gp.MemberOfSelector != nil || gp.MemberOf != nil {
		if gp.Database != nil || pc > 0 {
			return "", errors.New(errMemberOfWithDatabaseOrPrivileges)
		}
		return roleMember, nil
	}

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
	
	// Default database grant handling
	if gp.Database == nil {
		return "", errors.New(errNoDatabase)
	}

	if pc < 1 {
		return "", errors.New(errNoPrivileges)
	}

	// This is ROLE_DATABASE
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

		// Check if all requested privileges exist on all objects of the specified type
		q.String = `
			SELECT EXISTS (
				SELECT 1 FROM (
					SELECT cls.oid, cls.relnamespace, 
						array_agg(privilege_type ORDER BY privilege_type) as privileges
					FROM pg_class cls
					JOIN pg_namespace ns ON cls.relnamespace = ns.oid
					JOIN aclexplode(cls.relacl) acl ON true
					JOIN pg_roles r ON acl.grantee = r.oid
					WHERE ns.nspname = $1
					AND r.rolname = $2
					AND cls.relkind = $3
					GROUP BY cls.oid, cls.relnamespace
				) AS grants
				WHERE privileges @> $4::text[]
			)`

		q.Parameters = []interface{}{
			gp.Schema,
			gp.Role,
			objType,
			pq.Array(gp.Privileges.ToStringSlice()),
		}
		return nil
	case roleLargeObjects:
		q.String = `
			SELECT EXISTS (
				SELECT 1 FROM pg_largeobject_metadata pglm 
				INNER JOIN pg_authid pga ON pglm.lomowner = pga.oid
				WHERE pga.rolname = $1
				AND EXISTS (
					SELECT 1 FROM pg_largeobject_metadata lo
					JOIN aclexplode(lo.lomacl) acl ON true
					JOIN pg_roles r ON acl.grantee = r.oid
					WHERE lo.oid = pglm.oid
					AND r.rolname = $2
					AND array_agg(acl.privilege_type ORDER BY privilege_type) @> $3::text[]
				)
			)`

		q.Parameters = []interface{}{
			gp.LargeObjectOwner,
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

		*ql = append(*ql,
			// REVOKE ANY MATCHING EXISTING PERMISSIONS
			xsql.Query{String: fmt.Sprintf("REVOKE %s ON DATABASE %s FROM %s",
				sp,
				db,
				ro,
			)},

			// GRANT REQUESTED PERMISSIONS
			xsql.Query{String: fmt.Sprintf("GRANT %s ON DATABASE %s TO %s %s",
				sp,
				db,
				ro,
				withOption(gp.WithOption),
			)},
		)
		if gp.RevokePublicOnDb != nil && *gp.RevokePublicOnDb {
			*ql = append(*ql,
				// REVOKE FROM PUBLIC
				xsql.Query{String: fmt.Sprintf("REVOKE ALL ON DATABASE %s FROM PUBLIC",
					db,
				)},
			)
		}
		return nil
	case roleTables:
		sp := strings.Join(gp.Privileges.ToStringSlice(), ",")
		schema := pq.QuoteIdentifier(*gp.Schema)
		
		*ql = append(*ql,
			xsql.Query{String: fmt.Sprintf("REVOKE %s ON ALL TABLES IN SCHEMA %s FROM %s",
				sp,
				schema,
				ro,
			)},
			xsql.Query{String: fmt.Sprintf("GRANT %s ON ALL TABLES IN SCHEMA %s TO %s %s",
				sp,
				schema,
				ro,
				withOption(gp.WithOption),
			)},
		)
		return nil

	case roleSequences:
		sp := strings.Join(gp.Privileges.ToStringSlice(), ",")
		schema := pq.QuoteIdentifier(*gp.Schema)
		
		*ql = append(*ql,
			xsql.Query{String: fmt.Sprintf("REVOKE %s ON ALL SEQUENCES IN SCHEMA %s FROM %s",
				sp,
				schema,
				ro,
			)},
			xsql.Query{String: fmt.Sprintf("GRANT %s ON ALL SEQUENCES IN SCHEMA %s TO %s %s",
				sp,
				schema,
				ro,
				withOption(gp.WithOption),
			)},
		)
		return nil

	case roleFunctions:
		sp := strings.Join(gp.Privileges.ToStringSlice(), ",")
		schema := pq.QuoteIdentifier(*gp.Schema)
		
		*ql = append(*ql,
			xsql.Query{String: fmt.Sprintf("REVOKE %s ON ALL FUNCTIONS IN SCHEMA %s FROM %s",
				sp,
				schema,
				ro,
			)},
			xsql.Query{String: fmt.Sprintf("GRANT %s ON ALL FUNCTIONS IN SCHEMA %s TO %s %s",
				sp,
				schema,
				ro,
				withOption(gp.WithOption),
			)},
		)
		return nil
	case roleLargeObjects:
        if gp.Role == nil || gp.LargeObjectOwner == nil {
            return errors.Errorf(errInvalidParams, roleLargeObjects)
        }

        // First query finds all large objects owned by specified owner
        sp := strings.Join(gp.Privileges.ToStringSlice(), ",")
        ro := pq.QuoteIdentifier(*gp.Role)

        *ql = append(*ql,
            xsql.Query{String: fmt.Sprintf(
                "DO $$ DECLARE r record; "+
                "BEGIN "+
                "FOR r IN SELECT DISTINCT(pglm.oid) as oid FROM pg_largeobject_metadata pglm "+
                "INNER JOIN pg_authid pga ON pglm.lomowner = pga.oid "+
                "WHERE pga.rolname = '%s' "+
                "LOOP "+
                "EXECUTE 'GRANT %s ON LARGE OBJECT ' || r.oid || ' TO %s %s'; "+
                "END LOOP; END $$;",
                *gp.LargeObjectOwner,
                sp,
                ro,
                withOption(gp.WithOption),
            )},
        )
        return nil
	}
	return errors.New(errUnknownGrant)
}

func deleteGrantQuery(gp v1alpha1.GrantParameters, q *xsql.Query) error {
	gt, err := identifyGrantType(gp)
	if err != nil {
		return err
	}

	ro := pq.QuoteIdentifier(*gp.Role)

	switch gt {
	case roleMember:
		q.String = fmt.Sprintf("REVOKE %s FROM %s",
			pq.QuoteIdentifier(*gp.MemberOf),
			ro,
		)
		return nil
	case roleDatabase:
		q.String = fmt.Sprintf("REVOKE %s ON DATABASE %s FROM %s",
			strings.Join(gp.Privileges.ToStringSlice(), ","),
			pq.QuoteIdentifier(*gp.Database),
			ro,
		)
		return nil
	case roleTables, roleSequences, roleFunctions:
		sp := strings.Join(gp.Privileges.ToStringSlice(), ",")
		schema := pq.QuoteIdentifier(*gp.Schema)
		
		var objType string
		switch gt {
		case roleTables:
			objType = "TABLES"
		case roleSequences:
			objType = "SEQUENCES"
		case roleFunctions:
			objType = "FUNCTIONS"
		}
		
		q.String = fmt.Sprintf("REVOKE %s ON ALL %s IN SCHEMA %s FROM %s",
			sp,
			objType,
			schema,
			ro,
		)
		return nil
	}
	return errors.New(errUnknownGrant)
}

// Modified Observe method with clean SQL logging
func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.Grant)
	if (!ok) {
		return managed.ExternalObservation{}, errors.New(errNotGrant)
	}

	if cr.Spec.ForProvider.Role == nil {
		return managed.ExternalObservation{}, errors.New(errNoRole)
	}

	gp := cr.Spec.ForProvider
	var query xsql.Query
	if err := selectGrantQuery(gp, &query); err != nil {
		c.logger.Debug("[OBSERVE] Failed to build query", "error", err)
		return managed.ExternalObservation{}, err
	}

	// Log before execution with cleaned SQL
	c.logger.Debug("[OBSERVE] Executing SQL", "query", cleanSQLForLog(query.String), "parameters", query.Parameters)

	exists := false
	if err := c.db.Scan(ctx, query, &exists); err != nil {
		c.logger.Debug("[OBSERVE] Failed to execute SQL", "error", err)
		return managed.ExternalObservation{}, errors.Wrap(err, errSelectGrant)
	}

	if !exists {
		c.logger.Debug("[OBSERVE] Executed SQL WARN! Grant does not exist")
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	c.logger.Debug("[OBSERVE] Executed SQL OK. Grant exists")

	cr.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:          true,
		ResourceUpToDate:        true,
		ResourceLateInitialized: false,
	}, nil
}

// Modified Create method with clean SQL logging
func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.Grant)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotGrant)
	}

	var queries []xsql.Query

	cr.SetConditions(xpv1.Creating())

	if err := createGrantQueries(cr.Spec.ForProvider, &queries); err != nil {
		c.logger.Debug("[CREATE] Failed to build queries", "error", err)
		return managed.ExternalCreation{}, errors.Wrap(err, errCreateGrant)
	}

	// Log before execution with cleaned SQL
	for _, q := range queries {
		c.logger.Debug("[CREATE] Executing SQL", "query", cleanSQLForLog(q.String), "parameters", q.Parameters)
	}

	if err := c.db.ExecTx(ctx, queries); err != nil {
		c.logger.Debug("[CREATE] Failed to execute SQL", "error", err)
		return managed.ExternalCreation{}, errors.Wrap(err, errCreateGrant)
	}

	c.logger.Debug("[CREATE] Executed SQL OK")

	return managed.ExternalCreation{}, nil
}

// Modified Delete method with clean SQL logging
func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.Grant)
	if (!ok) {
		return errors.New(errNotGrant)
	}
	var query xsql.Query

	cr.SetConditions(xpv1.Deleting())

	if err := deleteGrantQuery(cr.Spec.ForProvider, &query); err != nil {
		c.logger.Debug("[DELETE] Failed to build query", "error", err)
		return errors.Wrap(err, errRevokeGrant)
	}

	// Log before execution with cleaned SQL
	c.logger.Debug("[DELETE] Executing SQL", "query", cleanSQLForLog(query.String), "parameters", query.Parameters)

	if err := c.db.Exec(ctx, query); err != nil {
		c.logger.Debug("[DELETE] Failed to execute SQL", "error", err)
		return errors.Wrap(err, errRevokeGrant)
	}

	c.logger.Debug("[DELETE] Executed SQL OK")

	return nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
    _, ok := mg.(*v1alpha1.Grant)
    if !ok {
        return managed.ExternalUpdate{}, errors.New(errNotGrant)
    }

    // Update is a no-op, as permissions are fully revoked and then granted in the Create function,
    // inside a transaction.
    c.logger.Debug("[UPDATE] No-op, permissions are handled in Create")
    
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
