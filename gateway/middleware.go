package gateway

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/TykTechnologies/tyk/internal/otel"
	"github.com/TykTechnologies/tyk/rpc"

	"github.com/TykTechnologies/tyk/header"

	"github.com/gocraft/health"
	"github.com/justinas/alice"
	newrelic "github.com/newrelic/go-agent"
	"github.com/paulbellamy/ratecounter"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/request"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/TykTechnologies/tyk/trace"
	"github.com/TykTechnologies/tyk/user"
)

const (
	mwStatusRespond                = 666
	DEFAULT_ORG_SESSION_EXPIRATION = int64(604800)
)

var (
	GlobalRate            = ratecounter.NewRateCounter(1 * time.Second)
	orgSessionExpiryCache singleflight.Group
)

type TykMiddleware interface {
	Init()
	Base() *BaseMiddleware

	SetName(string)
	SetRequestLogger(*http.Request)
	Logger() *logrus.Entry
	Config() (interface{}, error)
	ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) // Handles request
	EnabledForSpec() bool
	Name() string
}

type TraceMiddleware struct {
	TykMiddleware
}

func (tr TraceMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, conf interface{}) (error, int) {
	if trace.IsEnabled() {
		span, ctx := trace.Span(r.Context(),
			tr.Name(),
		)
		defer span.Finish()
		setContext(r, ctx)
		return tr.TykMiddleware.ProcessRequest(w, r, conf)
	} else if baseMw := tr.Base(); baseMw != nil {
		cfg := baseMw.Gw.GetConfig()
		if cfg.OpenTelemetry.Enabled {
			otel.AddTraceID(r.Context(), w)
			var span otel.Span
			if baseMw.Spec.DetailedTracing {
				var ctx context.Context
				ctx, span = baseMw.Gw.TracerProvider.Tracer().Start(r.Context(), tr.Name())
				defer span.End()
				setContext(r, ctx)
			} else {
				span = otel.SpanFromContext(r.Context())
			}

			err, i := tr.TykMiddleware.ProcessRequest(w, r, conf)
			if err != nil {
				span.SetStatus(otel.SPAN_STATUS_ERROR, err.Error())
			}

			attrs := ctxGetSpanAttributes(r, tr.TykMiddleware.Name())
			if len(attrs) > 0 {
				span.SetAttributes(attrs...)
			}

			return err, i
		}
	}

	return tr.TykMiddleware.ProcessRequest(w, r, conf)
}

func (gw *Gateway) createDynamicMiddleware(name string, isPre, useSession bool, baseMid *BaseMiddleware) func(http.Handler) http.Handler {
	dMiddleware := &DynamicMiddleware{
		BaseMiddleware:      baseMid,
		MiddlewareClassName: name,
		Pre:                 isPre,
		UseSession:          useSession,
	}

	return gw.createMiddleware(dMiddleware)
}

// Generic middleware caller to make extension easier
func (gw *Gateway) createMiddleware(actualMW TykMiddleware) func(http.Handler) http.Handler {
	mw := &TraceMiddleware{
		TykMiddleware: actualMW,
	}
	// construct a new instance
	mw.Init()
	mw.SetName(mw.Name())
	mw.Logger().Debug("Init")

	// Pull the configuration
	mwConf, err := mw.Config()
	if err != nil {
		mw.Logger().Fatal("[Middleware] Configuration load failed")
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mw.SetRequestLogger(r)

			if gw.GetConfig().NewRelic.AppName != "" {
				if txn, ok := w.(newrelic.Transaction); ok {
					defer newrelic.StartSegment(txn, mw.Name()).End()
				}
			}

			job := instrument.NewJob("MiddlewareCall")
			meta := health.Kvs{}
			eventName := mw.Name() + "." + "executed"

			if instrumentationEnabled {
				meta = health.Kvs{
					"from_ip":  request.RealIP(r),
					"method":   r.Method,
					"endpoint": r.URL.Path,
					"raw_url":  r.URL.String(),
					"size":     strconv.Itoa(int(r.ContentLength)),
					"mw_name":  mw.Name(),
				}
				job.EventKv("executed", meta)
				job.EventKv(eventName, meta)
			}

			startTime := time.Now()
			mw.Logger().WithField("ts", startTime.UnixNano()).Debug("Started")

			if mw.Base().Spec.CORS.OptionsPassthrough && r.Method == "OPTIONS" {
				h.ServeHTTP(w, r)
				return
			}

			err, errCode := mw.ProcessRequest(w, r, mwConf)
			if err != nil {
				writeResponse := true
				// Prevent double error write
				if goPlugin, isGoPlugin := actualMW.(*GoPluginMiddleware); isGoPlugin && goPlugin.handler != nil {
					writeResponse = false
				}

				handler := ErrorHandler{mw.Base()}
				handler.HandleError(w, r, err.Error(), errCode, writeResponse)

				meta["error"] = err.Error()

				finishTime := time.Since(startTime)

				if instrumentationEnabled {
					job.TimingKv("exec_time", finishTime.Nanoseconds(), meta)
					job.TimingKv(eventName+".exec_time", finishTime.Nanoseconds(), meta)
				}

				mw.Logger().WithError(err).WithField("code", errCode).WithField("ns", finishTime.Nanoseconds()).Debug("Finished")
				return
			}

			finishTime := time.Since(startTime)

			if instrumentationEnabled {
				job.TimingKv("exec_time", finishTime.Nanoseconds(), meta)
				job.TimingKv(eventName+".exec_time", finishTime.Nanoseconds(), meta)
			}

			mw.Logger().WithField("code", errCode).WithField("ns", finishTime.Nanoseconds()).Debug("Finished")

			// Special code, bypasses all other execution
			if errCode != mwStatusRespond {
				// No error, carry on...
				meta["bypass"] = "1"
				h.ServeHTTP(w, r)
			} else {
				mw.Base().UpdateRequestSession(r)
			}
		})
	}
}

func (gw *Gateway) mwAppendEnabled(chain *[]alice.Constructor, mw TykMiddleware) bool {
	if mw.EnabledForSpec() {
		*chain = append(*chain, gw.createMiddleware(mw))
		return true
	}
	return false
}

func (gw *Gateway) responseMWAppendEnabled(chain *[]TykResponseHandler, responseMW TykResponseHandler) bool {
	if responseMW.Enabled() {
		*chain = append(*chain, responseMW)
		return true
	}

	return false
}

func (gw *Gateway) mwList(mws ...TykMiddleware) []alice.Constructor {
	var list []alice.Constructor
	for _, mw := range mws {
		gw.mwAppendEnabled(&list, mw)
	}
	return list
}

// BaseMiddleware wraps up the ApiSpec and Proxy objects to be included in a
// middleware handler, this can probably be handled better.
type BaseMiddleware struct {
	Spec  *APISpec
	Proxy ReturningHttpHandler
	Gw    *Gateway `json:"-"`

	loggerMu sync.Mutex
	logger   *logrus.Entry
}

func (t *BaseMiddleware) Base() *BaseMiddleware {
	t.loggerMu.Lock()
	defer t.loggerMu.Unlock()

	return &BaseMiddleware{
		Spec:   t.Spec,
		Proxy:  t.Proxy,
		Gw:     t.Gw,
		logger: t.logger,
	}
}

func (t *BaseMiddleware) Logger() (logger *logrus.Entry) {
	t.loggerMu.Lock()
	defer t.loggerMu.Unlock()

	if t.logger == nil {
		t.logger = logrus.NewEntry(log)
	}

	return t.logger
}

func (t *BaseMiddleware) SetName(name string) {
	logger := t.Logger()

	t.loggerMu.Lock()
	defer t.loggerMu.Unlock()

	t.logger = logger.WithField("mw", name)
}

func (t *BaseMiddleware) SetRequestLogger(r *http.Request) {
	logger := t.Logger()

	t.loggerMu.Lock()
	defer t.loggerMu.Unlock()

	t.logger = t.Gw.getLogEntryForRequest(logger, r, ctxGetAuthToken(r), nil)
}

func (t *BaseMiddleware) Init() {}
func (t *BaseMiddleware) EnabledForSpec() bool {
	return true
}
func (t *BaseMiddleware) Config() (interface{}, error) {
	return nil, nil
}

func (t *BaseMiddleware) OrgSession(orgID string) (user.SessionState, bool) {

	if rpc.IsEmergencyMode() {
		return user.SessionState{}, false
	}

	// Try and get the session from the session store
	session, found := t.Spec.OrgSessionManager.SessionDetail(orgID, orgID, false)
	if found && t.Spec.GlobalConfig.EnforceOrgDataAge {
		// If exists, assume it has been authorized and pass on
		// We cache org expiry data
		t.Logger().Debug("Setting data expiry: ", orgID)

		t.Gw.ExpiryCache.Set(session.OrgID, session.DataExpires, cache.DefaultExpiration)
	}

	session.SetKeyHash(storage.HashKey(orgID, t.Gw.GetConfig().HashKeys))

	return session.Clone(), found
}

func (t *BaseMiddleware) SetOrgExpiry(orgid string, expiry int64) {
	t.Gw.ExpiryCache.Set(orgid, expiry, cache.DefaultExpiration)
}

func (t *BaseMiddleware) OrgSessionExpiry(orgid string) int64 {
	t.Logger().Debug("Checking: ", orgid)

	// Cache failed attempt
	id, err, _ := orgSessionExpiryCache.Do(orgid, func() (interface{}, error) {
		cachedVal, found := t.Gw.ExpiryCache.Get(orgid)
		if found {
			return cachedVal, nil
		}

		s, found := t.OrgSession(orgid)
		if found && t.Spec.GlobalConfig.EnforceOrgDataAge {
			return s.DataExpires, nil
		}
		return 0, errors.New("missing session")
	})

	if err != nil {
		t.Logger().Debug("no cached entry found, returning 7 days")
		t.SetOrgExpiry(orgid, DEFAULT_ORG_SESSION_EXPIRATION)
		return DEFAULT_ORG_SESSION_EXPIRATION
	}

	return id.(int64)
}

func (t *BaseMiddleware) UpdateRequestSession(r *http.Request) bool {
	session := ctxGetSession(r)
	token := ctxGetAuthToken(r)

	if session == nil || token == "" {
		return false
	}

	if !ctxSessionUpdateScheduled(r) {
		return false
	}

	lifetime := session.Lifetime(t.Spec.GetSessionLifetimeRespectsKeyExpiration(), t.Spec.SessionLifetime, t.Gw.GetConfig().ForceGlobalSessionLifetime, t.Gw.GetConfig().GlobalSessionLifetime)
	if err := t.Gw.GlobalSessionManager.UpdateSession(token, session, lifetime, false); err != nil {
		t.Logger().WithError(err).Error("Can't update session")
		return false
	}

	// Set context state back
	// Useful for benchmarks when request object stays same
	ctxDisableSessionUpdate(r)

	if !t.Spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState {
		t.Gw.SessionCache.Set(session.KeyHash(), session.Clone(), cache.DefaultExpiration)
	}

	return true
}

// clearSession clears the quota, rate limit and complexity values so that partitioned policies can apply their values.
// Otherwise, if the session has already a higher value, an applied policy will not win, and its values will be ignored.
func (t *BaseMiddleware) clearSession(session *user.SessionState) {
	policies := session.PolicyIDs()
	for _, polID := range policies {
		t.Gw.policiesMu.RLock()
		policy, ok := t.Gw.policiesByID[polID]
		t.Gw.policiesMu.RUnlock()
		if !ok {
			continue
		}

		all := !(policy.Partitions.Quota || policy.Partitions.RateLimit || policy.Partitions.Acl || policy.Partitions.Complexity)

		if policy.Partitions.Quota || all {
			session.QuotaMax = 0
			session.QuotaRemaining = 0
		}

		if policy.Partitions.RateLimit || all {
			session.Rate = 0
			session.Per = 0
			session.ThrottleRetryLimit = 0
			session.ThrottleInterval = 0
		}

		if policy.Partitions.Complexity || all {
			session.MaxQueryDepth = 0
		}
	}
}

// ApplyPolicies will check if any policies are loaded. If any are, it
// will overwrite the session state to use the policy values.
func (t *BaseMiddleware) ApplyPolicies(session *user.SessionState) error {
	rights := make(map[string]user.AccessDefinition)
	tags := make(map[string]bool)
	if session.MetaData == nil {
		session.MetaData = make(map[string]interface{})
	}

	t.clearSession(session)

	didQuota, didRateLimit, didACL, didComplexity := make(map[string]bool), make(map[string]bool), make(map[string]bool), make(map[string]bool)

	var (
		err       error
		lookupMap map[string]user.Policy
		policyIDs []string
	)

	customPolicies, err := session.CustomPolicies()
	if err != nil {
		policyIDs = session.PolicyIDs()
		t.Gw.policiesMu.RLock()
		lookupMap = t.Gw.policiesByID
		defer t.Gw.policiesMu.RUnlock()
	} else {
		lookupMap = customPolicies
		policyIDs = make([]string, 0, len(customPolicies))
		for _, val := range customPolicies {
			policyIDs = append(policyIDs, val.ID)
		}
	}

	for _, polID := range policyIDs {
		policy, ok := lookupMap[polID]
		if !ok {
			err := fmt.Errorf("policy not found: %q", polID)
			t.Logger().Error(err)
			if len(policyIDs) > 1 {
				continue
			}

			return err
		}
		// Check ownership, policy org owner must be the same as API,
		// otherwise you could overwrite a session key with a policy from a different org!
		if t.Spec != nil && policy.OrgID != t.Spec.OrgID {
			err := fmt.Errorf("attempting to apply policy from different organisation to key, skipping")
			t.Logger().Error(err)
			return err
		}

		if policy.Partitions.PerAPI &&
			(policy.Partitions.Quota || policy.Partitions.RateLimit || policy.Partitions.Acl || policy.Partitions.Complexity) {
			err := fmt.Errorf("cannot apply policy %s which has per_api and any of partitions set", policy.ID)
			log.Error(err)
			return err
		}

		if policy.Partitions.PerAPI {
			for apiID, accessRights := range policy.AccessRights {
				// new logic when you can specify quota or rate in more than one policy but for different APIs
				if didQuota[apiID] || didRateLimit[apiID] || didACL[apiID] || didComplexity[apiID] { // no other partitions allowed
					err := fmt.Errorf("cannot apply multiple policies when some have per_api set and some are partitioned")
					log.Error(err)
					return err
				}

				idForScope := apiID
				// check if we don't have limit on API level specified when policy was created
				if accessRights.Limit.IsEmpty() {
					// limit was not specified on API level so we will populate it from policy
					idForScope = policy.ID
					accessRights.Limit = user.APILimit{
						QuotaMax:           policy.QuotaMax,
						QuotaRenewalRate:   policy.QuotaRenewalRate,
						Rate:               policy.Rate,
						Per:                policy.Per,
						ThrottleInterval:   policy.ThrottleInterval,
						ThrottleRetryLimit: policy.ThrottleRetryLimit,
						MaxQueryDepth:      policy.MaxQueryDepth,
					}
				}
				accessRights.AllowanceScope = idForScope
				accessRights.Limit.SetBy = idForScope

				// respect current quota renews (on API limit level)
				if r, ok := session.AccessRights[apiID]; ok && !r.Limit.IsEmpty() {
					accessRights.Limit.QuotaRenews = r.Limit.QuotaRenews
				}

				if r, ok := session.AccessRights[apiID]; ok {
					// If GQL introspection is disabled, keep that configuration.
					if r.DisableIntrospection {
						accessRights.DisableIntrospection = r.DisableIntrospection
					}
				}

				// overwrite session access right for this API
				rights[apiID] = accessRights

				// identify that limit for that API is set (to allow set it only once)
				didACL[apiID] = true
				didQuota[apiID] = true
				didRateLimit[apiID] = true
				didComplexity[apiID] = true
			}
		} else {
			usePartitions := policy.Partitions.Quota || policy.Partitions.RateLimit || policy.Partitions.Acl || policy.Partitions.Complexity

			for k, v := range policy.AccessRights {
				ar := v

				if !usePartitions || policy.Partitions.Acl {
					didACL[k] = true

					ar.AllowedURLs = copyAllowedURLs(v.AllowedURLs)

					// Merge ACLs for the same API
					if r, ok := rights[k]; ok {
						// If GQL introspection is disabled, keep that configuration.
						if v.DisableIntrospection {
							r.DisableIntrospection = v.DisableIntrospection
						}
						r.Versions = appendIfMissing(rights[k].Versions, v.Versions...)

						for _, u := range v.AllowedURLs {
							found := false
							for ai, au := range r.AllowedURLs {
								if u.URL == au.URL {
									found = true
									r.AllowedURLs[ai].Methods = appendIfMissing(au.Methods, u.Methods...)
								}
							}

							if !found {
								r.AllowedURLs = append(r.AllowedURLs, v.AllowedURLs...)
							}
						}

						for _, t := range v.RestrictedTypes {
							for ri, rt := range r.RestrictedTypes {
								if t.Name == rt.Name {
									r.RestrictedTypes[ri].Fields = intersection(rt.Fields, t.Fields)
								}
							}
						}

						for _, t := range v.AllowedTypes {
							for ri, rt := range r.AllowedTypes {
								if t.Name == rt.Name {
									r.AllowedTypes[ri].Fields = intersection(rt.Fields, t.Fields)
								}
							}
						}

						mergeFieldLimits := func(res *user.FieldLimits, new user.FieldLimits) {
							if greaterThanInt(new.MaxQueryDepth, res.MaxQueryDepth) {
								res.MaxQueryDepth = new.MaxQueryDepth
							}
						}

						for _, far := range v.FieldAccessRights {
							exists := false
							for i, rfar := range r.FieldAccessRights {
								if far.TypeName == rfar.TypeName && far.FieldName == rfar.FieldName {
									exists = true
									mergeFieldLimits(&r.FieldAccessRights[i].Limits, far.Limits)
								}
							}

							if !exists {
								r.FieldAccessRights = append(r.FieldAccessRights, far)
							}
						}

						ar = r
					}

					ar.Limit.SetBy = policy.ID
				}

				if !usePartitions || policy.Partitions.Quota {
					didQuota[k] = true
					if greaterThanInt64(policy.QuotaMax, ar.Limit.QuotaMax) {

						ar.Limit.QuotaMax = policy.QuotaMax
						if greaterThanInt64(policy.QuotaMax, session.QuotaMax) {
							session.QuotaMax = policy.QuotaMax
						}
					}

					if policy.QuotaRenewalRate > ar.Limit.QuotaRenewalRate {
						ar.Limit.QuotaRenewalRate = policy.QuotaRenewalRate
						if policy.QuotaRenewalRate > session.QuotaRenewalRate {
							session.QuotaRenewalRate = policy.QuotaRenewalRate
						}
					}
				}

				if !usePartitions || policy.Partitions.RateLimit {
					didRateLimit[k] = true

					if greaterThanFloat64(policy.Rate, ar.Limit.Rate) {
						ar.Limit.Rate = policy.Rate
						if greaterThanFloat64(policy.Rate, session.Rate) {
							session.Rate = policy.Rate
						}
					}

					if policy.Per > ar.Limit.Per {
						ar.Limit.Per = policy.Per
						if policy.Per > session.Per {
							session.Per = policy.Per
						}
					}

					if policy.ThrottleRetryLimit > ar.Limit.ThrottleRetryLimit {
						ar.Limit.ThrottleRetryLimit = policy.ThrottleRetryLimit
						if policy.ThrottleRetryLimit > session.ThrottleRetryLimit {
							session.ThrottleRetryLimit = policy.ThrottleRetryLimit
						}
					}

					if policy.ThrottleInterval > ar.Limit.ThrottleInterval {
						ar.Limit.ThrottleInterval = policy.ThrottleInterval
						if policy.ThrottleInterval > session.ThrottleInterval {
							session.ThrottleInterval = policy.ThrottleInterval
						}
					}
				}

				if !usePartitions || policy.Partitions.Complexity {
					didComplexity[k] = true

					if greaterThanInt(policy.MaxQueryDepth, ar.Limit.MaxQueryDepth) {
						ar.Limit.MaxQueryDepth = policy.MaxQueryDepth
						if greaterThanInt(policy.MaxQueryDepth, session.MaxQueryDepth) {
							session.MaxQueryDepth = policy.MaxQueryDepth
						}
					}
				}

				// Respect existing QuotaRenews
				if r, ok := session.AccessRights[k]; ok && !r.Limit.IsEmpty() {
					ar.Limit.QuotaRenews = r.Limit.QuotaRenews
				}

				rights[k] = ar
			}

			// Master policy case
			if len(policy.AccessRights) == 0 {
				if !usePartitions || policy.Partitions.RateLimit {
					session.Rate = policy.Rate
					session.Per = policy.Per
					session.ThrottleInterval = policy.ThrottleInterval
					session.ThrottleRetryLimit = policy.ThrottleRetryLimit
				}

				if !usePartitions || policy.Partitions.Complexity {
					session.MaxQueryDepth = policy.MaxQueryDepth
				}

				if !usePartitions || policy.Partitions.Quota {
					session.QuotaMax = policy.QuotaMax
					session.QuotaRenewalRate = policy.QuotaRenewalRate
				}
			}

			if !session.HMACEnabled {
				session.HMACEnabled = policy.HMACEnabled
			}

			if !session.EnableHTTPSignatureValidation {
				session.EnableHTTPSignatureValidation = policy.EnableHTTPSignatureValidation
			}
		}

		session.IsInactive = session.IsInactive || policy.IsInactive

		for _, tag := range policy.Tags {
			tags[tag] = true
		}

		for k, v := range policy.MetaData {
			session.MetaData[k] = v
		}

		if policy.LastUpdated > session.LastUpdated {
			session.LastUpdated = policy.LastUpdated
		}
	}

	for _, tag := range session.Tags {
		tags[tag] = true
	}

	// set tags
	session.Tags = []string{}
	for tag := range tags {
		session.Tags = appendIfMissing(session.Tags, tag)
	}

	if len(policyIDs) == 0 {
		for apiID, accessRight := range session.AccessRights {
			// check if the api in the session has per api limit
			if !accessRight.Limit.IsEmpty() {
				accessRight.AllowanceScope = apiID
				session.AccessRights[apiID] = accessRight
			}
		}
	}

	distinctACL := make(map[string]bool)

	for _, v := range rights {
		if v.Limit.SetBy != "" {
			distinctACL[v.Limit.SetBy] = true
		}
	}

	// If some APIs had only ACL partitions, inherit rest from session level
	for k, v := range rights {
		if !didACL[k] {
			delete(rights, k)
			continue
		}

		if !didRateLimit[k] {
			v.Limit.Rate = session.Rate
			v.Limit.Per = session.Per
			v.Limit.ThrottleInterval = session.ThrottleInterval
			v.Limit.ThrottleRetryLimit = session.ThrottleRetryLimit
		}

		if !didComplexity[k] {
			v.Limit.MaxQueryDepth = session.MaxQueryDepth
		}

		if !didQuota[k] {
			v.Limit.QuotaMax = session.QuotaMax
			v.Limit.QuotaRenewalRate = session.QuotaRenewalRate
			v.Limit.QuotaRenews = session.QuotaRenews
		}

		// If multime ACL
		if len(distinctACL) > 1 {
			if v.AllowanceScope == "" && v.Limit.SetBy != "" {
				v.AllowanceScope = v.Limit.SetBy
			}
		}

		v.Limit.SetBy = ""

		rights[k] = v
	}

	// If we have policies defining rules for one single API, update session root vars (legacy)
	if len(didQuota) == 1 && len(didRateLimit) == 1 && len(didComplexity) == 1 {
		for _, v := range rights {
			if len(didRateLimit) == 1 {
				session.Rate = v.Limit.Rate
				session.Per = v.Limit.Per
			}

			if len(didQuota) == 1 {
				session.QuotaMax = v.Limit.QuotaMax
				session.QuotaRenews = v.Limit.QuotaRenews
				session.QuotaRenewalRate = v.Limit.QuotaRenewalRate
			}

			if len(didComplexity) == 1 {
				session.MaxQueryDepth = v.Limit.MaxQueryDepth
			}
		}
	}

	// Override session ACL if at least one policy define it
	if len(didACL) > 0 {
		session.AccessRights = rights
	}

	return nil
}

func copyAllowedURLs(input []user.AccessSpec) []user.AccessSpec {
	if input == nil {
		return nil
	}

	copied := make([]user.AccessSpec, len(input))

	for i, as := range input {
		copied[i] = user.AccessSpec{
			URL: as.URL,
		}
		if as.Methods != nil {
			copied[i].Methods = make([]string, len(as.Methods))
			copy(copied[i].Methods, as.Methods)
		}
	}

	return copied
}

// CheckSessionAndIdentityForValidKey will check first the Session store for a valid key, if not found, it will try
// the Auth Handler, if not found it will fail
func (t *BaseMiddleware) CheckSessionAndIdentityForValidKey(originalKey string, r *http.Request) (user.SessionState, bool) {
	key := originalKey
	minLength := t.Spec.GlobalConfig.MinTokenLength
	if minLength == 0 {
		// See https://github.com/TykTechnologies/tyk/issues/1681
		minLength = 3
	}

	if len(key) <= minLength {
		return user.SessionState{IsInactive: true}, false
	}

	// Try and get the session from the session store
	t.Logger().Debug("Querying local cache")
	keyHash := key
	cacheKey := key
	if t.Spec.GlobalConfig.HashKeys {
		cacheKey = storage.HashStr(key, storage.HashMurmur64) // always hash cache keys with murmur64 to prevent collisions
	}

	// Check in-memory cache
	if !t.Spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState {
		cachedVal, found := t.Gw.SessionCache.Get(cacheKey)
		if found {
			t.Logger().Debug("--> Key found in local cache")
			session := cachedVal.(user.SessionState).Clone()
			if err := t.ApplyPolicies(&session); err != nil {
				t.Logger().Error(err)
				return session, false
			}
			return session, true
		}
	}

	// Check session store
	t.Logger().Debug("Querying keystore")
	session, found := t.Gw.GlobalSessionManager.SessionDetail(t.Spec.OrgID, key, false)

	if found {
		if t.Spec.GlobalConfig.HashKeys {
			keyHash = storage.HashStr(session.KeyID)
		}
		session := session.Clone()
		session.SetKeyHash(keyHash)
		// If exists, assume it has been authorized and pass on
		// cache it
		if !t.Spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState {
			t.Gw.SessionCache.Set(cacheKey, session, cache.DefaultExpiration)
		}

		// Check for a policy, if there is a policy, pull it and overwrite the session values
		if err := t.ApplyPolicies(&session); err != nil {
			t.Logger().Error(err)
			return session, false
		}
		t.Logger().Debug("Got key")
		return session, true
	}

	if _, ok := t.Spec.AuthManager.Store().(*RPCStorageHandler); ok && rpc.IsEmergencyMode() {
		return session.Clone(), false
	}

	// Only search in RPC if it's not in emergency mode
	t.Logger().Debug("Querying authstore")
	// 2. If not there, get it from the AuthorizationHandler
	session, found = t.Spec.AuthManager.SessionDetail(t.Spec.OrgID, key, false)
	if found {
		key = session.KeyID

		session := session.Clone()
		session.SetKeyHash(keyHash)
		// If not in Session, and got it from AuthHandler, create a session with a new TTL
		t.Logger().Info("Recreating session for key: ", t.Gw.obfuscateKey(key))

		// cache it
		if !t.Spec.GlobalConfig.LocalSessionCache.DisableCacheSessionState {
			go t.Gw.SessionCache.Set(cacheKey, session, cache.DefaultExpiration)
		}

		// Check for a policy, if there is a policy, pull it and overwrite the session values
		if err := t.ApplyPolicies(&session); err != nil {
			t.Logger().Error(err)
			return session, false
		}

		t.Logger().Debug("Lifetime is: ", session.Lifetime(t.Spec.GetSessionLifetimeRespectsKeyExpiration(), t.Spec.SessionLifetime, t.Gw.GetConfig().ForceGlobalSessionLifetime, t.Gw.GetConfig().GlobalSessionLifetime))
		ctxScheduleSessionUpdate(r)
		return session, found
	}

	// session not found
	session.KeyID = key
	return session, false
}

// FireEvent is added to the BaseMiddleware object so it is available across the entire stack
func (t *BaseMiddleware) FireEvent(name apidef.TykEvent, meta interface{}) {
	fireEvent(name, meta, t.Spec.EventPaths)
}

func (t *BaseMiddleware) getAuthType() string {
	return ""
}

func (t *BaseMiddleware) getAuthToken(authType string, r *http.Request) (string, apidef.AuthConfig) {
	spec := t.Base().Spec
	config, ok := spec.AuthConfigs[authType]
	// Auth is deprecated. To maintain backward compatibility authToken and jwt cases are added.
	if !ok && (authType == apidef.AuthTokenType || authType == apidef.JWTType) {
		config = spec.Auth
	}

	var (
		key         string
		defaultName = header.Authorization
	)

	headerName := config.AuthHeaderName
	if !config.DisableHeader {
		if headerName == "" {
			headerName = defaultName
		} else {
			defaultName = headerName
		}

		key = r.Header.Get(headerName)
	}

	paramName := config.ParamName
	if config.UseParam {
		if paramName == "" {
			paramName = defaultName
		}

		paramValue := r.URL.Query().Get(paramName)

		// Only use the paramValue if it has an actual value
		if paramValue != "" {
			key = paramValue
		}
	}

	cookieName := config.CookieName
	if config.UseCookie {
		if cookieName == "" {
			cookieName = defaultName
		}

		authCookie, err := r.Cookie(cookieName)
		cookieValue := ""
		if err == nil {
			cookieValue = authCookie.Value
		}

		if cookieValue != "" {
			key = cookieValue
		}
	}

	return key, config
}

func (t *BaseMiddleware) generateSessionID(id string) string {
	// generate a virtual token
	data := []byte(id)
	keyID := fmt.Sprintf("%x", md5.Sum(data))
	return t.Gw.generateToken(t.Spec.OrgID, keyID)
}

type TykResponseHandler interface {
	Enabled() bool
	Init(interface{}, *APISpec) error
	Name() string
	HandleResponse(http.ResponseWriter, *http.Response, *http.Request, *user.SessionState) error
	HandleError(http.ResponseWriter, *http.Request)
	Base() *BaseTykResponseHandler
}

type TykGoPluginResponseHandler interface {
	TykResponseHandler
	HandleGoPluginResponse(http.ResponseWriter, *http.Response, *http.Request) error
}

func (gw *Gateway) responseProcessorByName(name string, baseHandler BaseTykResponseHandler) TykResponseHandler {
	switch name {
	case "response_body_transform_jq":
		return &ResponseTransformJQMiddleware{BaseTykResponseHandler: baseHandler}
	case "header_transform":
		return &HeaderTransform{BaseTykResponseHandler: baseHandler}
	case "custom_mw_res_hook":
		return &CustomMiddlewareResponseHook{BaseTykResponseHandler: baseHandler}
	case "goplugin_res_hook":
		return &ResponseGoPluginMiddleware{BaseTykResponseHandler: baseHandler}
	}

	return nil
}

func handleResponseChain(chain []TykResponseHandler, rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) (abortRequest bool, err error) {

	if res.Request != nil {
		// res.Request context contains otel information from the otel roundtripper
		setContext(req, res.Request.Context())
	}

	traceIsEnabled := trace.IsEnabled()
	for _, rh := range chain {
		if err := handleResponse(rh, rw, res, req, ses, traceIsEnabled); err != nil {
			// Abort the request if this handler is a response middleware hook:
			if rh.Name() == "CustomMiddlewareResponseHook" {
				rh.HandleError(rw, req)
				return true, err
			}
			return false, err
		}
	}
	return false, nil
}

func handleResponse(rh TykResponseHandler, rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState, shouldTrace bool) error {
	if shouldTrace {
		span, ctx := trace.Span(req.Context(), rh.Name())
		defer span.Finish()
		req = req.WithContext(ctx)
	} else if rh.Base().Gw.GetConfig().OpenTelemetry.Enabled {
		return handleOtelTracedResponse(rh, rw, res, req, ses)
	}
	return rh.HandleResponse(rw, res, req, ses)
}

// handleOtelTracedResponse handles the tracing for the response middlewares when
// otel is enabled in the gateway
func handleOtelTracedResponse(rh TykResponseHandler, rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	var span otel.Span
	var err error

	baseMw := rh.Base()
	if baseMw == nil {
		return errors.New("unsupported base middleware")
	}

	// ResponseCacheMiddleware always executes but not always caches,so check if we must create the span
	shouldTrace := shouldPerformTracing(rh, baseMw)
	ctx := req.Context()
	if shouldTrace {
		if baseMw.Spec.DetailedTracing {
			ctx, span = baseMw.Gw.TracerProvider.Tracer().Start(ctx, rh.Name())
			defer span.End()
			setContext(req, ctx)
		} else {
			span = otel.SpanFromContext(ctx)
		}

		err = rh.HandleResponse(rw, res, req, ses)

		if err != nil {
			span.SetStatus(otel.SPAN_STATUS_ERROR, err.Error())
		}

		attrs := ctxGetSpanAttributes(req, rh.Name())
		if len(attrs) > 0 {
			span.SetAttributes(attrs...)
		}
	} else {
		err = rh.HandleResponse(rw, res, req, ses)
	}

	return err
}

func shouldPerformTracing(rh TykResponseHandler, baseMw *BaseTykResponseHandler) bool {
	return rh.Name() != "ResponseCacheMiddleware" || baseMw.Spec.CacheOptions.EnableCache
}

func parseForm(r *http.Request) {
	// https://golang.org/pkg/net/http/#Request.ParseForm
	// ParseForm drains the request body for a request with Content-Type of
	// application/x-www-form-urlencoded
	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" && r.Form == nil {
		var b bytes.Buffer
		r.Body = ioutil.NopCloser(io.TeeReader(r.Body, &b))

		r.ParseForm()

		r.Body = ioutil.NopCloser(&b)
		return
	}

	r.ParseForm()
}

type BaseTykResponseHandler struct {
	Spec *APISpec `json:"-"`
	Gw   *Gateway `json:"-"`
}

func (b *BaseTykResponseHandler) Enabled() bool {
	return true
}

func (b *BaseTykResponseHandler) Init(i interface{}, spec *APISpec) error {
	return nil
}

func (b *BaseTykResponseHandler) Name() string {
	return "BaseTykResponseHandler"
}

func (b *BaseTykResponseHandler) HandleResponse(rw http.ResponseWriter, res *http.Response, req *http.Request, ses *user.SessionState) error {
	return nil
}

func (b *BaseTykResponseHandler) HandleError(writer http.ResponseWriter, h *http.Request) {}
