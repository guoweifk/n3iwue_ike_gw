package message

import "fmt"

// IKE types
type IkePayloadType uint8

const (
	NoNext IkePayloadType = 0
	TypeSA IkePayloadType = iota + 32
	TypeKE
	TypeIDi
	TypeIDr
	TypeCERT
	TypeCERTreq
	TypeAUTH
	TypeNiNr
	TypeN
	TypeD
	TypeV
	TypeTSi
	TypeTSr
	TypeSK
	TypeCP
	TypeEAP
)

var typeStr map[IkePayloadType]string = map[IkePayloadType]string{
	NoNext:      "NoNext",
	TypeSA:      "SA",
	TypeKE:      "KE",
	TypeIDi:     "IDi",
	TypeIDr:     "IDr",
	TypeCERT:    "CERT",
	TypeCERTreq: "CERTreq",
	TypeAUTH:    "AUTH",
	TypeNiNr:    "NiNr",
	TypeN:       "N",
	TypeD:       "D",
	TypeV:       "V",
	TypeTSi:     "TSi",
	TypeTSr:     "TSr",
	TypeSK:      "SK",
	TypeCP:      "CP",
	TypeEAP:     "EAP",
}

// RFC 7296: 3.2.  Generic Payload Header
func (t IkePayloadType) String() string {
	s, ok := typeStr[t]
	if !ok {
		return fmt.Sprintf("IKE payload type[%d] is not supported", t)
	}
	return s
}

// used for SecurityAssociation-Proposal-Transform TransformType
const (
	TypeEncryptionAlgorithm = iota + 1
	TypePseudorandomFunction
	TypeIntegrityAlgorithm
	TypeDiffieHellmanGroup
	TypeExtendedSequenceNumbers
)

// used for SecurityAssociation-Proposal-Transform AttributeFormat
const (
	AttributeFormatUseTLV = iota
	AttributeFormatUseTV
)

// used for SecurityAssociation-Proposal-Trandform AttributeType
const (
	AttributeTypeKeyLength = 14
)

// used for SecurityAssociation-Proposal-Transform TransformID
const (
	ENCR_DES_IV64 = 1
	ENCR_DES      = 2
	ENCR_3DES     = 3
	ENCR_RC5      = 4
	ENCR_IDEA     = 5
	ENCR_CAST     = 6
	ENCR_BLOWFISH = 7
	ENCR_3IDEA    = 8
	ENCR_DES_IV32 = 9
	ENCR_NULL     = 11
	ENCR_AES_CBC  = 12
	ENCR_AES_CTR  = 13
)

const (
	PRF_HMAC_MD5 = iota + 1
	PRF_HMAC_SHA1
	PRF_HMAC_TIGER
	PRF_HMAC_SHA2_256 = 5
)

const (
	AUTH_NONE = iota
	AUTH_HMAC_MD5_96
	AUTH_HMAC_SHA1_96
	AUTH_DES_MAC
	AUTH_KPDK_MD5
	AUTH_AES_XCBC_96
	AUTH_HMAC_SHA2_256_128 = 12
)

const (
	DH_NONE          = 0
	DH_768_BIT_MODP  = 1
	DH_1024_BIT_MODP = 2
	DH_1536_BIT_MODP = 5
	DH_2048_BIT_MODP = iota + 10
	DH_3072_BIT_MODP
	DH_4096_BIT_MODP
	DH_6144_BIT_MODP
	DH_8192_BIT_MODP
)

const (
	ESN_DISABLE = iota
	ESN_ENABLE
)

// used for TrafficSelector-Individual Traffic Selector TSType
const (
	TS_IPV4_ADDR_RANGE = 7
	TS_IPV6_ADDR_RANGE = 8
)

// Exchange Type
const (
	IKE_SA_INIT = iota + 34
	IKE_AUTH
	CREATE_CHILD_SA
	INFORMATIONAL
)

// Notify message types
const (
	UNSUPPORTED_CRITICAL_PAYLOAD  = 1
	INVALID_IKE_SPI               = 4
	INVALID_MAJOR_VERSION         = 5
	INVALID_SYNTAX                = 7
	INVALID_MESSAGE_ID            = 9
	INVALID_SPI                   = 11
	NO_PROPOSAL_CHOSEN            = 14
	INVALID_KE_PAYLOAD            = 17
	AUTHENTICATION_FAILED         = 24
	SINGLE_PAIR_REQUIRED          = 34
	NO_ADDITIONAL_SAS             = 35
	INTERNAL_ADDRESS_FAILURE      = 36
	FAILED_CP_REQUIRED            = 37
	TS_UNACCEPTABLE               = 38
	INVALID_SELECTORS             = 39
	UNACCEPTABLE_ADDRESSES        = 40
	UNEXPECTED_NAT_DETECTED       = 41
	TEMPORARY_FAILURE             = 43
	CHILD_SA_NOT_FOUND            = 44
	INITIAL_CONTACT               = 16384
	SET_WINDOW_SIZE               = 16385
	ADDITIONAL_TS_POSSIBLE        = 16386
	IPCOMP_SUPPORTED              = 16387
	NAT_DETECTION_SOURCE_IP       = 16388
	NAT_DETECTION_DESTINATION_IP  = 16389
	COOKIE                        = 16390
	USE_TRANSPORT_MODE            = 16391
	HTTP_CERT_LOOKUP_SUPPORTED    = 16392
	REKEY_SA                      = 16393
	ESP_TFC_PADDING_NOT_SUPPORTED = 16394
	NON_FIRST_FRAGMENTS_ALSO      = 16395
	MOBIKE_SUPPORTED              = 16396
	ADDITIONAL_IP4_ADDRESS        = 16397
	ADDITIONAL_IP6_ADDRESS        = 16398
	NO_ADDITIONAL_ADDRESSES       = 16399
	UPDATE_SA_ADDRESSES           = 16400
	COOKIE2                       = 16401
	NO_NATS_ALLOWED               = 16402
	P_N1_MODE_CAPABILITY          = 51015
)

// Protocol ID
const (
	TypeNone = iota
	TypeIKE
	TypeAH
	TypeESP
)

// Certificate encoding
const (
	PKCS7WrappedX509Certificate = 1
	PGPCertificate              = 2
	DNSSignedKey                = 3
	X509CertificateSignature    = 4
	KerberosToken               = 6
	CertificateRevocationList   = 7
	AuthorityRevocationList     = 8
	SPKICertificate             = 9
	X509CertificateAttribute    = 10
	HashAndURLOfX509Certificate = 12
	HashAndURLOfX509Bundle      = 13
)

// ID Types
const (
	ID_IPV4_ADDR   = 1
	ID_FQDN        = 2
	ID_RFC822_ADDR = 3
	ID_IPV6_ADDR   = 5
	ID_DER_ASN1_DN = 9
	ID_DER_ASN1_GN = 10
	ID_KEY_ID      = 11
)

// Authentication Methods
const (
	RSADigitalSignature = iota + 1
	SharedKeyMesageIntegrityCode
	DSSDigitalSignature
)

// Configuration types
const (
	CFG_REQUEST = 1
	CFG_REPLY   = 2
	CFG_SET     = 3
	CFG_ACK     = 4
)

// Configuration attribute types
const (
	INTERNAL_IP4_ADDRESS = 1
	INTERNAL_IP4_NETMASK = 2
	INTERNAL_IP4_DNS     = 3
	INTERNAL_IP4_NBNS    = 4
	INTERNAL_IP4_DHCP    = 6
	APPLICATION_VERSION  = 7
	INTERNAL_IP6_ADDRESS = 8
	INTERNAL_IP6_DNS     = 10
	INTERNAL_IP6_DHCP    = 12
	INTERNAL_IP4_SUBNET  = 13
	SUPPORTED_ATTRIBUTES = 14
	INTERNAL_IP6_SUBNET  = 15
	P_CSCF_IP4_ADDRESS   = 20
	P_CSCF_IP6_ADDRESS   = 21
)

// IP protocols ID, used in individual traffic selector
const (
	IPProtocolAll  = 0
	IPProtocolICMP = 1
	IPProtocolTCP  = 6
	IPProtocolUDP  = 17
	IPProtocolGRE  = 47
)

// Used in EAP-5G for message ID
const (
	EAP5GType5GStart = 1
	EAP5GType5GNAS   = 2
	EAP5GType5GStop  = 4
)

// Spare
const EAP5GSpareValue = 0

// Used in AN-Parameter field for IE types
const (
	ANParametersTypeGUAMI              = 1
	ANParametersTypeSelectedPLMNID     = 2
	ANParametersTypeRequestedNSSAI     = 3
	ANParametersTypeEstablishmentCause = 4
)

// Used for checking if AN-Parameter length field is legal
const (
	ANParametersLenGUAMI    = 6
	ANParametersLenPLMNID   = 3
	ANParametersLenEstCause = 1
)

// Used in IE Establishment Cause field for cause types
const (
	EstablishmentCauseEmergency          = 0
	EstablishmentCauseHighPriorityAccess = 1
	EstablishmentCauseMO_Signaling       = 3
	EstablishmentCauseMO_Data            = 4
	EstablishmentCauseMPS_PriorityAccess = 8
	EstablishmentCauseMCS_PriorityAccess = 9
)

// 3GPP specified IKE Notify Message Types
const (
	Vendor3GPPNotifyType5G_QOS_INFO     uint16 = 55501
	Vendor3GPPNotifyTypeNAS_IP4_ADDRESS uint16 = 55502
	Vendor3GPPNotifyTypeUP_IP4_ADDRESS  uint16 = 55504
	Vendor3GPPNotifyTypeNAS_TCP_PORT    uint16 = 55506
)

// Used in NotifyType5G_QOS_INFO
const (
	NotifyType5G_QOS_INFOBitDSCPICheck uint8 = 1 << iota
	NotifyType5G_QOS_INFOBitDCSICheck
)

// IKE role
type Role bool

const (
	Role_Initiator Role = true
	Role_Responder Role = false
)
