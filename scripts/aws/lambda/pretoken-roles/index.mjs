// Cognito Pre Token Generation (V1) trigger for the shared Mesh admin app client's user pool.
//
// Mesh's own authorization code (AdminRoleAuthorizationHandler, WorkflowController's
// ExtractHitlContextFromClaims) reads roles from a claim literally named "roles" only. Cognito
// never emits one natively — it only emits "cognito:groups". This trigger bridges that gap by
// adding a "roles" claim derived from group membership, additively, to the ID token.
//
// Safety properties (do not weaken these — this pool backs Mesh's own real user login, not just
// this demo):
//   - ADDITIVE ONLY. Never sets claimsToSuppress. Never touches any claim other than "roles".
//   - FAIL OPEN. Any unexpected error is caught and swallowed; the event is returned unmodified
//     so login always proceeds. A thrown/unhandled error here would fail the auth attempt for
//     every user of this pool, not just this demo's users.
//   - No network calls, no dependencies — pure synchronous mapping from the event's own group
//     list, so there's nothing here that can hang or time out.

const GROUP_TO_ROLE = {
  "mesh-admins": "mesh.admin",
};

export const handler = async (event) => {
  try {
    const groups = event?.request?.groupConfiguration?.groupsToOverride ?? [];
    const groupList = Array.isArray(groups) ? groups : [];

    const roles = [...new Set(groupList.map((g) => GROUP_TO_ROLE[g]).filter(Boolean))];

    if (roles.length > 0) {
      event.response = event.response ?? {};
      event.response.claimsOverrideDetails = {
        claimsToAddOrOverride: {
          roles: roles.join(","),
        },
      };
    }
  } catch (err) {
    console.error("pretoken-roles trigger failed; returning event unmodified so login still succeeds:", err);
  }

  return event;
};
