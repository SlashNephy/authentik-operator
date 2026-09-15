/*
Copyright 2026 SlashNephy.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// AuthentikApplicationSpec defines the desired state of an authentik Application, its Provider, and its access rights.
// Optional fields that are omitted are not managed; see docs/spec.md §2.
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.provider) || has(self.provider)",message="provider cannot be removed once set; recreate the resource instead"
type AuthentikApplicationSpec struct {
	// slug is the unique identifier of the Application in authentik. It cannot be changed after creation.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[-a-zA-Z0-9_]+$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="slug is immutable"
	Slug string `json:"slug"`

	// name is the display name of the Application.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// launchURL is the URL opened from the library view.
	// +optional
	LaunchURL *string `json:"launchURL,omitempty"`

	// icon is an https:// URL, a fa:// Font Awesome icon, or another path supported by the authentik file backends.
	// +optional
	Icon *string `json:"icon,omitempty"`

	// description is shown in the library view.
	// +optional
	Description *string `json:"description,omitempty"`

	// publisher is shown in the library view.
	// +optional
	Publisher *string `json:"publisher,omitempty"`

	// group is the display group in the library view. It is not an authentik Group.
	// +optional
	Group *string `json:"group,omitempty"`

	// openInNewTab opens the launch URL in a new browser tab.
	// +optional
	OpenInNewTab *bool `json:"openInNewTab,omitempty"`

	// hideFromApplicationDashboard hides the Application from the library view (meta_hide).
	// +optional
	HideFromApplicationDashboard *bool `json:"hideFromApplicationDashboard,omitempty"`

	// deletionPolicy controls what happens to the authentik objects when this resource is deleted.
	// +optional
	// +kubebuilder:default=Retain
	DeletionPolicy *DeletionPolicy `json:"deletionPolicy,omitempty"`

	// adopt controls whether existing objects that the operator does not manage are adopted.
	// +optional
	// +kubebuilder:default=Never
	Adopt *AdoptionPolicy `json:"adopt,omitempty"`

	// provider is the Provider attached to the Application. When omitted, the Application has no Provider.
	// Once set, it cannot be removed and its type cannot be changed.
	// +optional
	Provider *ProviderSpec `json:"provider,omitempty"`

	// access defines who can access the Application.
	// +required
	Access AccessSpec `json:"access"`
}

// DeletionPolicy controls what happens to the authentik objects when the resource is deleted.
// +kubebuilder:validation:Enum=Retain;Delete
type DeletionPolicy string

const (
	// DeletionPolicyRetain keeps the objects in authentik and only removes the ownership markers.
	DeletionPolicyRetain DeletionPolicy = "Retain"
	// DeletionPolicyDelete deletes the managed Bindings, the Application, and the Provider.
	DeletionPolicyDelete DeletionPolicy = "Delete"
)

// AdoptionPolicy controls whether unmanaged objects are adopted.
// +kubebuilder:validation:Enum=Never;IfMatch;Force
type AdoptionPolicy string

const (
	// AdoptionPolicyNever leaves unmanaged objects untouched.
	AdoptionPolicyNever AdoptionPolicy = "Never"
	// AdoptionPolicyIfMatch adopts unmanaged objects only when every managed field matches.
	AdoptionPolicyIfMatch AdoptionPolicy = "IfMatch"
	// AdoptionPolicyForce adopts unmanaged objects by overwriting them with the spec.
	AdoptionPolicyForce AdoptionPolicy = "Force"
)

// ProviderSpec defines the Provider attached to the Application.
// +kubebuilder:validation:XValidation:rule="has(self.proxy) != has(self.oauth2)",message="exactly one of proxy or oauth2 must be specified"
// +kubebuilder:validation:XValidation:rule="has(self.proxy) == has(oldSelf.proxy)",message="the provider type cannot be changed; recreate the resource instead"
type ProviderSpec struct {
	// name is the Provider name. Defaults to the slug when the Provider is created.
	// +optional
	// +kubebuilder:validation:MinLength=1
	Name *string `json:"name,omitempty"`

	// flows are the flows used by the Provider.
	// +required
	Flows ProviderFlows `json:"flows"`

	// proxy configures a Proxy Provider.
	// +optional
	Proxy *ProxyProviderSpec `json:"proxy,omitempty"`

	// oauth2 configures an OAuth2/OpenID Provider.
	// +optional
	OAuth2 *OAuth2ProviderSpec `json:"oauth2,omitempty"`
}

// ProviderFlows are the flows used by a Provider.
type ProviderFlows struct {
	// authorization is the flow used to authorize access to the Provider.
	// +required
	Authorization FlowReference `json:"authorization"`

	// invalidation is the flow used when the session ends.
	// +required
	Invalidation FlowReference `json:"invalidation"`

	// authentication is the flow used when a user has to authenticate.
	// +optional
	Authentication *FlowReference `json:"authentication,omitempty"`
}

// ProxyProviderSpec configures a Proxy Provider.
// +kubebuilder:validation:XValidation:rule="(has(self.proxy) ? 1 : 0) + (has(self.forwardAuthSingle) ? 1 : 0) + (has(self.forwardAuthDomain) ? 1 : 0) == 1",message="exactly one of proxy, forwardAuthSingle, or forwardAuthDomain must be specified"
type ProxyProviderSpec struct {
	// proxy runs authentik as a reverse proxy in front of the application (mode=proxy).
	// +optional
	Proxy *ProxyModeSpec `json:"proxy,omitempty"`

	// forwardAuthSingle uses forward auth for a single application (mode=forward_single).
	// +optional
	ForwardAuthSingle *ForwardAuthSingleSpec `json:"forwardAuthSingle,omitempty"`

	// forwardAuthDomain uses forward auth for every application under a domain (mode=forward_domain).
	// +optional
	ForwardAuthDomain *ForwardAuthDomainSpec `json:"forwardAuthDomain,omitempty"`

	// unauthenticatedPaths are regular expressions of paths that do not require authentication (skip_path_regex).
	// +optional
	// +listType=atomic
	UnauthenticatedPaths []string `json:"unauthenticatedPaths,omitempty"`

	// basicAuth sends HTTP Basic credentials taken from user or group attributes to the application.
	// +optional
	BasicAuth *BasicAuthSpec `json:"basicAuth,omitempty"`

	// interceptHeaderAuth lets authentik handle the Authorization header.
	// +optional
	InterceptHeaderAuth *bool `json:"interceptHeaderAuth,omitempty"`

	// accessTokenValidity is a duration such as hours=24.
	// +optional
	AccessTokenValidity *string `json:"accessTokenValidity,omitempty"`

	// refreshTokenValidity is a duration such as days=30.
	// +optional
	RefreshTokenValidity *string `json:"refreshTokenValidity,omitempty"`

	// certificate is the CertificateKeyPair used for TLS.
	// +optional
	Certificate *NamedReference `json:"certificate,omitempty"`

	// outpost is the Outpost that serves the Provider. Defaults to the embedded outpost.
	// +optional
	Outpost *NamedReference `json:"outpost,omitempty"`
}

// ProxyModeSpec configures mode=proxy.
type ProxyModeSpec struct {
	// externalHost is the URL that users access.
	// +required
	// +kubebuilder:validation:MinLength=1
	ExternalHost string `json:"externalHost"`

	// internalHost is the URL of the upstream application.
	// +required
	// +kubebuilder:validation:MinLength=1
	InternalHost string `json:"internalHost"`

	// internalHostSSLValidation validates the TLS certificate of the internal host.
	// +optional
	InternalHostSSLValidation *bool `json:"internalHostSSLValidation,omitempty"`
}

// ForwardAuthSingleSpec configures mode=forward_single.
type ForwardAuthSingleSpec struct {
	// externalHost is the URL that users access.
	// +required
	// +kubebuilder:validation:MinLength=1
	ExternalHost string `json:"externalHost"`
}

// ForwardAuthDomainSpec configures mode=forward_domain.
type ForwardAuthDomainSpec struct {
	// authenticationURL is the URL of authentik used for the domain (external_host).
	// +required
	// +kubebuilder:validation:MinLength=1
	AuthenticationURL string `json:"authenticationURL"`

	// cookieDomain is the domain that the session cookie is set for.
	// +required
	// +kubebuilder:validation:MinLength=1
	CookieDomain string `json:"cookieDomain"`
}

// BasicAuthSpec configures HTTP Basic credentials sent to the application.
type BasicAuthSpec struct {
	// userAttribute is the user or group attribute that holds the username.
	// +required
	// +kubebuilder:validation:MinLength=1
	UserAttribute string `json:"userAttribute"`

	// passwordAttribute is the user or group attribute that holds the password.
	// +required
	// +kubebuilder:validation:MinLength=1
	PasswordAttribute string `json:"passwordAttribute"`
}

// OAuth2ProviderSpec configures an OAuth2/OpenID Provider.
type OAuth2ProviderSpec struct {
	// clientType is the OAuth2 client type.
	// +optional
	ClientType *ClientType `json:"clientType,omitempty"`

	// redirectURIs are the allowed redirect URIs.
	// +optional
	// +listType=atomic
	RedirectURIs []RedirectURI `json:"redirectURIs,omitempty"`

	// scopes are the ScopeMappings available to the client. Defaults to openid, email, and profile on creation.
	// +optional
	// +listType=atomic
	Scopes []ScopeMappingReference `json:"scopes,omitempty"`

	// signingKey is the CertificateKeyPair used to sign tokens. Defaults to the authentik self-signed certificate on creation.
	// +optional
	SigningKey *NamedReference `json:"signingKey,omitempty"`

	// encryptionKey is the CertificateKeyPair used to encrypt tokens.
	// +optional
	EncryptionKey *NamedReference `json:"encryptionKey,omitempty"`

	// grantTypes are the allowed grant types.
	// +optional
	// +listType=set
	GrantTypes []GrantType `json:"grantTypes,omitempty"`

	// subjectMode controls the value of the sub claim.
	// +optional
	SubjectMode *SubjectMode `json:"subjectMode,omitempty"`

	// issuerMode controls the issuer of the tokens.
	// +optional
	IssuerMode *IssuerMode `json:"issuerMode,omitempty"`

	// includeClaimsInIDToken includes the user claims in the ID token.
	// +optional
	IncludeClaimsInIDToken *bool `json:"includeClaimsInIDToken,omitempty"`

	// accessCodeValidity is a duration such as minutes=1.
	// +optional
	AccessCodeValidity *string `json:"accessCodeValidity,omitempty"`

	// accessTokenValidity is a duration such as minutes=5.
	// +optional
	AccessTokenValidity *string `json:"accessTokenValidity,omitempty"`

	// refreshTokenValidity is a duration such as days=30.
	// +optional
	RefreshTokenValidity *string `json:"refreshTokenValidity,omitempty"`

	// refreshTokenThreshold is a duration such as seconds=0.
	// +optional
	RefreshTokenThreshold *string `json:"refreshTokenThreshold,omitempty"`

	// logoutURI is the URI notified when the user logs out.
	// +optional
	LogoutURI *string `json:"logoutURI,omitempty"`

	// logoutMethod is the way logoutURI is notified.
	// +optional
	LogoutMethod *LogoutMethod `json:"logoutMethod,omitempty"`

	// credentials manages the client ID and client secret with a Secret as the source of truth.
	// +optional
	Credentials *OAuth2CredentialsSpec `json:"credentials,omitempty"`
}

// ClientType is the OAuth2 client type.
// +kubebuilder:validation:Enum=Confidential;Public
type ClientType string

const (
	// ClientTypeConfidential is a client that can keep a secret.
	ClientTypeConfidential ClientType = "Confidential"
	// ClientTypePublic is a client that cannot keep a secret.
	ClientTypePublic ClientType = "Public"
)

// GrantType is an OAuth2 grant type.
// +kubebuilder:validation:Enum=AuthorizationCode;Implicit;Hybrid;RefreshToken;ClientCredentials;Password;DeviceCode;TokenExchange
type GrantType string

const (
	// GrantTypeAuthorizationCode is authorization_code.
	GrantTypeAuthorizationCode GrantType = "AuthorizationCode"
	// GrantTypeImplicit is implicit.
	GrantTypeImplicit GrantType = "Implicit"
	// GrantTypeHybrid is hybrid.
	GrantTypeHybrid GrantType = "Hybrid"
	// GrantTypeRefreshToken is refresh_token.
	GrantTypeRefreshToken GrantType = "RefreshToken"
	// GrantTypeClientCredentials is client_credentials.
	GrantTypeClientCredentials GrantType = "ClientCredentials"
	// GrantTypePassword is password.
	GrantTypePassword GrantType = "Password"
	// GrantTypeDeviceCode is urn:ietf:params:oauth:grant-type:device_code.
	GrantTypeDeviceCode GrantType = "DeviceCode"
	// GrantTypeTokenExchange is urn:ietf:params:oauth:grant-type:token-exchange.
	GrantTypeTokenExchange GrantType = "TokenExchange"
)

// SubjectMode controls the value of the sub claim (sub_mode).
// +kubebuilder:validation:Enum=HashedUserID;UserID;UserUUID;UserUsername;UserEmail;UserUPN
type SubjectMode string

const (
	// SubjectModeHashedUserID is hashed_user_id.
	SubjectModeHashedUserID SubjectMode = "HashedUserID"
	// SubjectModeUserID is user_id.
	SubjectModeUserID SubjectMode = "UserID"
	// SubjectModeUserUUID is user_uuid.
	SubjectModeUserUUID SubjectMode = "UserUUID"
	// SubjectModeUserUsername is user_username.
	SubjectModeUserUsername SubjectMode = "UserUsername"
	// SubjectModeUserEmail is user_email.
	SubjectModeUserEmail SubjectMode = "UserEmail"
	// SubjectModeUserUPN is user_upn.
	SubjectModeUserUPN SubjectMode = "UserUPN"
)

// IssuerMode controls the issuer of the tokens.
// +kubebuilder:validation:Enum=Global;PerProvider
type IssuerMode string

const (
	// IssuerModeGlobal is global.
	IssuerModeGlobal IssuerMode = "Global"
	// IssuerModePerProvider is per_provider.
	IssuerModePerProvider IssuerMode = "PerProvider"
)

// LogoutMethod is the way the logout URI is notified.
// +kubebuilder:validation:Enum=BackChannel;FrontChannel
type LogoutMethod string

const (
	// LogoutMethodBackChannel is backchannel.
	LogoutMethodBackChannel LogoutMethod = "BackChannel"
	// LogoutMethodFrontChannel is frontchannel.
	LogoutMethodFrontChannel LogoutMethod = "FrontChannel"
)

// RedirectURI is an allowed redirect URI.
type RedirectURI struct {
	// url is the redirect URI, or a regular expression when matchingMode is Regex.
	// +required
	// +kubebuilder:validation:MinLength=1
	URL string `json:"url"`

	// matchingMode controls how url is compared.
	// +optional
	// +kubebuilder:default=Strict
	MatchingMode *MatchingMode `json:"matchingMode,omitempty"`

	// type is the purpose of the redirect URI.
	// +optional
	// +kubebuilder:default=Authorization
	Type *RedirectURIType `json:"type,omitempty"`
}

// MatchingMode controls how a redirect URI is compared.
// +kubebuilder:validation:Enum=Strict;Regex
type MatchingMode string

const (
	// MatchingModeStrict compares the URI exactly.
	MatchingModeStrict MatchingMode = "Strict"
	// MatchingModeRegex compares the URI with a regular expression.
	MatchingModeRegex MatchingMode = "Regex"
)

// RedirectURIType is the purpose of a redirect URI.
// +kubebuilder:validation:Enum=Authorization;PostLogout
type RedirectURIType string

const (
	// RedirectURITypeAuthorization is authorization.
	RedirectURITypeAuthorization RedirectURIType = "Authorization"
	// RedirectURITypePostLogout is logout.
	RedirectURITypePostLogout RedirectURIType = "PostLogout"
)

// OAuth2CredentialsSpec manages the client ID and client secret with a Secret as the source of truth.
// +kubebuilder:validation:XValidation:rule="!(has(self.clientID) && has(self.secretRef.clientIDKey))",message="clientID and secretRef.clientIDKey are mutually exclusive"
type OAuth2CredentialsSpec struct {
	// clientID is the client ID. When omitted, it is read from the Secret.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	ClientID *string `json:"clientID,omitempty"`

	// secretRef is the Secret in the same namespace that holds the credentials.
	// +required
	SecretRef OAuth2CredentialsSecretReference `json:"secretRef"`
}

// OAuth2CredentialsSecretReference refers to a Secret that holds OAuth2 client credentials.
type OAuth2CredentialsSecretReference struct {
	// name is the name of the Secret.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// clientIDKey is the key that holds the client ID. Defaults to client-id.
	// +optional
	// +kubebuilder:validation:MinLength=1
	ClientIDKey *string `json:"clientIDKey,omitempty"`

	// clientSecretKey is the key that holds the client secret. Defaults to client-secret.
	// +optional
	// +kubebuilder:validation:MinLength=1
	ClientSecretKey *string `json:"clientSecretKey,omitempty"`
}

// AccessSpec defines who can access the Application.
// +kubebuilder:validation:XValidation:rule="(has(self.rules) && size(self.rules) > 0) || (has(self.public) && self.public)",message="at least one rule is required unless public is true"
// +kubebuilder:validation:XValidation:rule="!(has(self.rules) && size(self.rules) > 0 && has(self.public) && self.public)",message="public must be false when rules are specified"
type AccessSpec struct {
	// mode is the policy engine mode of the Application (policy_engine_mode).
	// +optional
	// +kubebuilder:default=Any
	Mode *AccessMode `json:"mode,omitempty"`

	// rules are the Bindings attached to the Application.
	// +optional
	// +listType=atomic
	Rules []AccessRule `json:"rules,omitempty"`

	// public makes the Application accessible to every user. It requires rules to be empty.
	// +optional
	// +kubebuilder:default=false
	Public *bool `json:"public,omitempty"`

	// prune deletes Bindings on the Application that the operator does not manage.
	// +optional
	// +kubebuilder:default=false
	Prune *bool `json:"prune,omitempty"`
}

// AccessMode is the policy engine mode.
// +kubebuilder:validation:Enum=Any;All
type AccessMode string

const (
	// AccessModeAny passes when any Binding passes.
	AccessModeAny AccessMode = "Any"
	// AccessModeAll passes when every Binding passes.
	AccessModeAll AccessMode = "All"
)

// AccessRule is a Binding to a Group, a User, or a Policy.
// +kubebuilder:validation:XValidation:rule="(has(self.group) ? 1 : 0) + (has(self.user) ? 1 : 0) + (has(self.policy) ? 1 : 0) == 1",message="exactly one of group, user, or policy must be specified"
type AccessRule struct {
	// group is the Group to bind. Members of child groups also pass.
	// +optional
	Group *NamedReference `json:"group,omitempty"`

	// user is the User to bind.
	// +optional
	User *UserReference `json:"user,omitempty"`

	// policy is the Policy to bind.
	// +optional
	Policy *NamedReference `json:"policy,omitempty"`

	// negate inverts the result of the Binding.
	// +optional
	Negate *bool `json:"negate,omitempty"`
}

// NamedReference refers to an authentik object by its unique name or its UUID.
// It is used for Groups, Policies, CertificateKeyPairs, and Outposts.
// +kubebuilder:validation:XValidation:rule="has(self.name) != has(self.uuid)",message="exactly one of name or uuid must be specified"
type NamedReference struct {
	// name is the name of the object.
	// +optional
	// +kubebuilder:validation:MinLength=1
	Name *string `json:"name,omitempty"`

	// uuid is the UUID of the object.
	// +optional
	// +kubebuilder:validation:Format=uuid
	UUID *string `json:"uuid,omitempty"`
}

// FlowReference refers to an authentik Flow by its slug or its UUID.
// +kubebuilder:validation:XValidation:rule="has(self.slug) != has(self.uuid)",message="exactly one of slug or uuid must be specified"
type FlowReference struct {
	// slug is the slug of the Flow.
	// +optional
	// +kubebuilder:validation:MinLength=1
	Slug *string `json:"slug,omitempty"`

	// uuid is the UUID of the Flow.
	// +optional
	// +kubebuilder:validation:Format=uuid
	UUID *string `json:"uuid,omitempty"`
}

// UserReference refers to an authentik User by its username or its integer primary key.
// +kubebuilder:validation:XValidation:rule="has(self.username) != has(self.pk)",message="exactly one of username or pk must be specified"
type UserReference struct {
	// username is the username of the User.
	// +optional
	// +kubebuilder:validation:MinLength=1
	Username *string `json:"username,omitempty"`

	// pk is the primary key of the User.
	// +optional
	// +kubebuilder:validation:Minimum=1
	PK *int64 `json:"pk,omitempty"`
}

// ScopeMappingReference refers to an authentik ScopeMapping by its scope name or its UUID.
// +kubebuilder:validation:XValidation:rule="has(self.scopeName) != has(self.uuid)",message="exactly one of scopeName or uuid must be specified"
type ScopeMappingReference struct {
	// scopeName is the scope that clients request (scope_name).
	// +optional
	// +kubebuilder:validation:MinLength=1
	ScopeName *string `json:"scopeName,omitempty"`

	// uuid is the UUID of the ScopeMapping.
	// +optional
	// +kubebuilder:validation:Format=uuid
	UUID *string `json:"uuid,omitempty"`
}

// Condition types of AuthentikApplication.
const (
	// ConditionTypeReady summarizes whether the resource is reconciled.
	ConditionTypeReady = "Ready"
	// ConditionTypeUnmanagedBindings reports Bindings on the Application that the operator does not manage.
	ConditionTypeUnmanagedBindings = "UnmanagedBindings"
)

// Reasons of the Ready condition when it is False.
const (
	// ReasonConflict means another resource with the same slug won.
	ReasonConflict = "Conflict"
	// ReasonUnmanaged means an unmanaged object exists and adopt is Never.
	ReasonUnmanaged = "Unmanaged"
	// ReasonAdoptionDiff means adopt is IfMatch and the managed fields differ.
	ReasonAdoptionDiff = "AdoptionDiff"
	// ReasonProviderTypeMismatch means the existing Provider has a different type.
	ReasonProviderTypeMismatch = "ProviderTypeMismatch"
	// ReasonUnmanagedBindings means public is true, prune is false, and unmanaged Bindings remain.
	ReasonUnmanagedBindings = "UnmanagedBindings"
	// ReasonReferenceNotFound means a reference cannot be resolved.
	ReasonReferenceNotFound = "ReferenceNotFound"
	// ReasonAmbiguousReference means a reference matches several objects.
	ReasonAmbiguousReference = "AmbiguousReference"
	// ReasonAPIError means the authentik API returned an error.
	ReasonAPIError = "APIError"
)

// AuthentikApplicationStatus defines the observed state of AuthentikApplication.
type AuthentikApplicationStatus struct {
	// observedGeneration is the generation of the spec that was last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// applicationSlug is the slug of the managed Application.
	// +optional
	ApplicationSlug string `json:"applicationSlug,omitempty"`

	// applicationPK is the primary key of the managed Application.
	// +optional
	ApplicationPK string `json:"applicationPK,omitempty"`

	// providerPK is the primary key of the managed Provider.
	// +optional
	ProviderPK *int64 `json:"providerPK,omitempty"`

	// bindingUUIDs are the UUIDs of the managed Bindings.
	// +optional
	// +listType=set
	BindingUUIDs []string `json:"bindingUUIDs,omitempty"`

	// lastAppliedHash is the hash of the spec that was last applied to authentik.
	// +optional
	LastAppliedHash string `json:"lastAppliedHash,omitempty"`

	// adoptionDiff lists the managed fields that differ when adopt is IfMatch. Confidential values are redacted.
	// +optional
	// +listType=atomic
	AdoptionDiff []FieldDiff `json:"adoptionDiff,omitempty"`

	// unmanagedBindings lists the Bindings on the Application that the operator does not manage.
	// +optional
	// +listType=atomic
	UnmanagedBindings []UnmanagedBinding `json:"unmanagedBindings,omitempty"`

	// conditions represent the current state of the resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// FieldDiff is a managed field whose actual value differs from the desired value.
type FieldDiff struct {
	// field is the path of the field in the spec.
	// +required
	Field string `json:"field"`

	// desired is the value in the spec.
	// +optional
	Desired string `json:"desired,omitempty"`

	// actual is the value in authentik.
	// +optional
	Actual string `json:"actual,omitempty"`
}

// UnmanagedBinding is a Binding on the Application that the operator does not manage.
type UnmanagedBinding struct {
	// uuid is the UUID of the Binding.
	// +required
	UUID string `json:"uuid"`

	// target describes the subject of the Binding, such as group/legacy.
	// +optional
	Target string `json:"target,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=akapp
// +kubebuilder:printcolumn:name="Slug",type=string,JSONPath=`.spec.slug`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AuthentikApplication manages an authentik Application together with its Provider and access rights.
type AuthentikApplication struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of AuthentikApplication
	// +required
	Spec AuthentikApplicationSpec `json:"spec"`

	// status defines the observed state of AuthentikApplication
	// +optional
	Status AuthentikApplicationStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// AuthentikApplicationList contains a list of AuthentikApplication
type AuthentikApplicationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []AuthentikApplication `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(scheme *runtime.Scheme) error {
		scheme.AddKnownTypes(SchemeGroupVersion, &AuthentikApplication{}, &AuthentikApplicationList{})
		return nil
	})
}
