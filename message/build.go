package message

import (
	"encoding/binary"
	"net"

	"github.com/pkg/errors"

	eap_message "github.com/guoweifk/n3iwue_ike_gw/eap"
)

func (container *IKEPayloadContainer) Reset() {
	*container = nil
}

func (container *IKEPayloadContainer) BuildNotification(
	protocolID uint8,
	notifyMessageType uint16,
	spi []byte,
	notificationData []byte,
) {
	notification := new(Notification)
	notification.ProtocolID = protocolID
	notification.NotifyMessageType = notifyMessageType
	notification.SPI = append(notification.SPI, spi...)
	notification.NotificationData = append(notification.NotificationData, notificationData...)
	*container = append(*container, notification)
}

func (container *IKEPayloadContainer) BuildCertificate(certificateEncode uint8, certificateData []byte) {
	certificate := new(Certificate)
	certificate.CertificateEncoding = certificateEncode
	certificate.CertificateData = append(certificate.CertificateData, certificateData...)
	*container = append(*container, certificate)
}

func (container *IKEPayloadContainer) BuildEncrypted(nextPayload IkePayloadType,
	encryptedData []byte,
) *Encrypted {
	encrypted := new(Encrypted)
	encrypted.NextPayload = uint8(nextPayload)
	encrypted.EncryptedData = append(encrypted.EncryptedData, encryptedData...)
	*container = append(*container, encrypted)
	return encrypted
}

func (container *IKEPayloadContainer) BuildKeyExchange(diffiehellmanGroup uint16, keyExchangeData []byte) {
	keyExchange := new(KeyExchange)
	keyExchange.DiffieHellmanGroup = diffiehellmanGroup
	keyExchange.KeyExchangeData = append(keyExchange.KeyExchangeData, keyExchangeData...)
	*container = append(*container, keyExchange)
}

func (container *IKEPayloadContainer) BuildIdentificationInitiator(idType uint8, idData []byte) {
	identification := new(IdentificationInitiator)
	identification.IDType = idType
	identification.IDData = append(identification.IDData, idData...)
	*container = append(*container, identification)
}

func (container *IKEPayloadContainer) BuildIdentificationResponder(idType uint8, idData []byte) {
	identification := new(IdentificationResponder)
	identification.IDType = idType
	identification.IDData = append(identification.IDData, idData...)
	*container = append(*container, identification)
}

func (container *IKEPayloadContainer) BuildAuthentication(authenticationMethod uint8, authenticationData []byte) {
	authentication := new(Authentication)
	authentication.AuthenticationMethod = authenticationMethod
	authentication.AuthenticationData = append(authentication.AuthenticationData, authenticationData...)
	*container = append(*container, authentication)
}

func (container *IKEPayloadContainer) BuildConfiguration(configurationType uint8) *Configuration {
	configuration := new(Configuration)
	configuration.ConfigurationType = configurationType
	*container = append(*container, configuration)
	return configuration
}

func (container *ConfigurationAttributeContainer) Reset() {
	*container = nil
}

func (container *ConfigurationAttributeContainer) BuildConfigurationAttribute(
	attributeType uint16,
	attributeValue []byte,
) {
	configurationAttribute := new(IndividualConfigurationAttribute)
	configurationAttribute.Type = attributeType
	configurationAttribute.Value = append(configurationAttribute.Value, attributeValue...)
	*container = append(*container, configurationAttribute)
}

func (container *IKEPayloadContainer) BuildNonce(nonceData []byte) {
	nonce := new(Nonce)
	nonce.NonceData = append(nonce.NonceData, nonceData...)
	*container = append(*container, nonce)
}

func (container *IKEPayloadContainer) BuildTrafficSelectorInitiator() *TrafficSelectorInitiator {
	trafficSelectorInitiator := new(TrafficSelectorInitiator)
	*container = append(*container, trafficSelectorInitiator)
	return trafficSelectorInitiator
}

func (container *IKEPayloadContainer) BuildTrafficSelectorResponder() *TrafficSelectorResponder {
	trafficSelectorResponder := new(TrafficSelectorResponder)
	*container = append(*container, trafficSelectorResponder)
	return trafficSelectorResponder
}

func (container *IndividualTrafficSelectorContainer) Reset() {
	*container = nil
}

func (container *IndividualTrafficSelectorContainer) BuildIndividualTrafficSelector(
	tsType uint8,
	ipProtocolID uint8,
	startPort uint16,
	endPort uint16,
	startAddr []byte,
	endAddr []byte,
) {
	trafficSelector := new(IndividualTrafficSelector)
	trafficSelector.TSType = tsType
	trafficSelector.IPProtocolID = ipProtocolID
	trafficSelector.StartPort = startPort
	trafficSelector.EndPort = endPort
	trafficSelector.StartAddress = append(trafficSelector.StartAddress, startAddr...)
	trafficSelector.EndAddress = append(trafficSelector.EndAddress, endAddr...)
	*container = append(*container, trafficSelector)
}

func (container *IKEPayloadContainer) BuildSecurityAssociation() *SecurityAssociation {
	securityAssociation := new(SecurityAssociation)
	*container = append(*container, securityAssociation)
	return securityAssociation
}

func (container *ProposalContainer) Reset() {
	*container = nil
}

func (container *ProposalContainer) BuildProposal(proposalNumber uint8, protocolID uint8, spi []byte) *Proposal {
	proposal := new(Proposal)
	proposal.ProposalNumber = proposalNumber
	proposal.ProtocolID = protocolID
	proposal.SPI = append(proposal.SPI, spi...)
	*container = append(*container, proposal)
	return proposal
}

func (container *IKEPayloadContainer) BuildDeletePayload(
	protocolID uint8, spiSize uint8, numberOfSPI uint16, spis []uint32,
) {
	deletePayload := new(Delete)
	deletePayload.ProtocolID = protocolID
	deletePayload.SPISize = spiSize
	deletePayload.NumberOfSPI = numberOfSPI
	deletePayload.SPIs = spis
	*container = append(*container, deletePayload)
}

func (container *TransformContainer) Reset() {
	*container = nil
}

func (container *TransformContainer) BuildTransform(
	transformType uint8,
	transformID uint16,
	attributeType *uint16,
	attributeValue *uint16,
	variableLengthAttributeValue []byte,
) {
	transform := new(Transform)
	transform.TransformType = transformType
	transform.TransformID = transformID
	if attributeType != nil {
		transform.AttributePresent = true
		transform.AttributeType = *attributeType
		if attributeValue != nil {
			transform.AttributeFormat = AttributeFormatUseTV
			transform.AttributeValue = *attributeValue
		} else if len(variableLengthAttributeValue) != 0 {
			transform.AttributeFormat = AttributeFormatUseTLV
			transform.VariableLengthAttributeValue = append(
				transform.VariableLengthAttributeValue,
				variableLengthAttributeValue...)
		} else {
			return
		}
	} else {
		transform.AttributePresent = false
	}
	*container = append(*container, transform)
}

func (container *IKEPayloadContainer) BuildEAP(code eap_message.EapCode, identifier uint8) *PayloadEap {
	eap := &PayloadEap{
		EAP: &eap_message.EAP{
			Code:       code,
			Identifier: identifier,
		},
	}

	*container = append(*container, eap)
	return eap
}

func BuildEAPAKAEapTypeData(subtype eap_message.EapAkaSubtype, attributeMap map[eap_message.EapAkaAttrType]*eap_message.EapAkaAttr) *eap_message.EapAka {

	eapAka := new(eap_message.EapAka)
	eapAka.SubType = subtype
	eapAka.Attributes = attributeMap

	return eapAka
}
func pad4(b []byte) []byte {
	if m := len(b) % 4; m != 0 {
		return append(b, make([]byte, 4-m)...)
	}
	return b
}
func akaAttrLen(valuePaddedLen int) uint8 {
	total := 4 + valuePaddedLen // 头(4B) + 对齐后的 Value
	return uint8(total / 4)
}

func BuildEapAkaAttr(attrType eap_message.EapAkaAttrType, vStr string, vBytes []byte) *eap_message.EapAkaAttr {

	switch attrType {
	case eap_message.AKA_AT_IDENTITY: // AT_IDENTITY
		idBytes := []byte(vStr)
		pad := (4 - (len(idBytes) % 4)) % 4
		paddedLen := len(idBytes) + pad // Value 长度(含padding)
		l := uint8((4 + paddedLen) / 4) // 头4B + Value，再除以4

		return &eap_message.EapAkaAttr{
			AttrType:            attrType,            // 14
			Length:              l,                   // 例如 60/4=15
			Identity_actual_len: uint8(len(idBytes)), // 54
			Identity:            vStr,                // "0505030000000001@nai.epc.mnc003.mcc505.3gppnetwork.org"
			Padding:             "0000",
		}

	case eap_message.AKA_AT_RES: // AT_RES
		// resBytes 是你算出来的 8B RES（不是 hex 字符串）
		resBytes := vBytes

		// Value = 2B 位长(大端) + RES
		val := make([]byte, 2+len(resBytes))
		binary.BigEndian.PutUint16(val[:2], uint16(len(resBytes)*8)) // 8B -> 64 -> 0x0040
		copy(val[2:], resBytes)

		// 计算 Length（单位4字节：Type+Len=2B，剩下是 val，再补零对齐）
		total := 2 + len(val)
		if pad := (4 - (total % 4)) % 4; pad > 0 {
			val = append(val, make([]byte, pad)...)
			total += pad
		}
		l := uint8(total / 4)

		return &eap_message.EapAkaAttr{
			AttrType: eap_message.AKA_AT_RES,
			Length:   l,
			Value:    val, // 已含“位长+RES(+pad)”
		}

	//case eap_message.AKA_AT_MAC:
	//	// 如果传进来的是十六进制字符串（例如 "0000ecb1be7e..."），要先 decode
	//
	//	l := akaAttrLen(len(vBytes))
	//
	//	return &eap_message.EapAkaAttr{
	//		AttrType: attrType,
	//		Length:   l,
	//		Value:    vBytes,
	//	}
	case eap_message.AKA_AT_MAC:
		// vBytes 是你算出来的 16B MAC
		//if len(vBytes) != 16 {
		//	return nil, fmt.Errorf("AT_MAC: expect 16-byte MAC, got %d", len(vBytes))
		//}

		// 2B Reserved(0x0000) + MAC(16B)
		val := make([]byte, 2+len(vBytes))
		// Reserved 默认 0x0000
		copy(val[2:], vBytes)

		// 计算 Length (单位 4B)
		total := 2 /*Type+Len*/ + len(val)
		if pad := (4 - (total % 4)) % 4; pad > 0 {
			val = append(val, make([]byte, pad)...)
			total += pad
		}
		l := uint8(total / 4)

		return &eap_message.EapAkaAttr{
			AttrType: attrType,
			Length:   l,
			Value:    val, // 已含 reserved+mac(+pad)
		}

	default:
		return nil
	}

}

func (container *IKEPayloadContainer) BuildEAPSuccess(identifier uint8) {
	eap := &PayloadEap{
		EAP: &eap_message.EAP{
			Code:       eap_message.EapCodeSuccess,
			Identifier: identifier,
		},
	}

	*container = append(*container, eap)
}

func (container *IKEPayloadContainer) BuildEAPfailure(identifier uint8) {
	eap := &PayloadEap{
		EAP: &eap_message.EAP{
			Code:       eap_message.EapCodeFailure,
			Identifier: identifier,
		},
	}

	*container = append(*container, eap)
}

func BuildEapExpanded(vendorID uint32, vendorType uint32, vendorData []byte) *eap_message.EapExpanded {
	eapExpanded := new(eap_message.EapExpanded)
	eapExpanded.VendorID = vendorID
	eapExpanded.VendorType = vendorType
	eapExpanded.VendorData = append(eapExpanded.VendorData, vendorData...)

	return eapExpanded
}

func (container *IKEPayloadContainer) BuildEAP5GStart(identifier uint8) {
	eap := container.BuildEAP(eap_message.EapCodeRequest, identifier)
	eap.EapTypeData = BuildEapExpanded(eap_message.VendorId3GPP, eap_message.VendorTypeEAP5G,
		[]byte{EAP5GType5GStart, EAP5GSpareValue})
}

func (container *IKEPayloadContainer) BuildEAP5GNAS(identifier uint8, nasPDU []byte) error {
	if len(nasPDU) == 0 {
		return errors.Errorf("BuildEAP5GNAS(): NASPDU is nil")
	}
	var vendorData []byte
	header := make([]byte, 4)

	// Message ID
	header[0] = EAP5GType5GNAS
	// NASPDU length (2 octets)
	nasPDULen := len(nasPDU)
	if nasPDULen > 0xFFFF {
		return errors.Errorf("BuildEAP5GNAS(): nasPDU length exceeds uint16 limit: %d", nasPDULen)
	}
	binary.BigEndian.PutUint16(header[2:4], uint16(nasPDULen))
	vendorData = append(vendorData, header...)
	vendorData = append(vendorData, nasPDU...)

	eap := container.BuildEAP(eap_message.EapCodeRequest, identifier)
	eap.EapTypeData = BuildEapExpanded(eap_message.VendorId3GPP, eap_message.VendorTypeEAP5G, vendorData)

	return nil
}

func (container *IKEPayloadContainer) BuildNotify5G_QOS_INFO(
	pduSessionID uint8,
	qfiList []uint8,
	isDefault bool,
	isDSCPSpecified bool,
	dscp uint8,
) error {
	notifyData := make([]byte, 1) // For length
	// Append PDU session ID
	notifyData = append(notifyData, pduSessionID)
	// Append QFI list length
	qfiListLen := len(qfiList)
	if qfiListLen > 0xFF {
		return errors.Errorf("BuildNotify5G_QOS_INFO(): qfiList is too long")
	}
	notifyData = append(notifyData, uint8(qfiListLen))
	// Append QFI list
	notifyData = append(notifyData, qfiList...)
	// Append default and differentiated service flags
	var defaultAndDifferentiatedServiceFlags uint8
	if isDefault {
		defaultAndDifferentiatedServiceFlags |= NotifyType5G_QOS_INFOBitDCSICheck
	}
	if isDSCPSpecified {
		defaultAndDifferentiatedServiceFlags |= NotifyType5G_QOS_INFOBitDSCPICheck
	}

	notifyData = append(notifyData, defaultAndDifferentiatedServiceFlags)
	if isDSCPSpecified {
		notifyData = append(notifyData, dscp)
	}

	// Assign length
	notifyDataLen := len(notifyData)
	if notifyDataLen > 0xFF {
		return errors.Errorf("BuildNotify5G_QOS_INFO(): notifyData is too long")
	}
	notifyData[0] = uint8(notifyDataLen)

	container.BuildNotification(TypeNone, Vendor3GPPNotifyType5G_QOS_INFO, nil, notifyData)
	return nil
}

func (container *IKEPayloadContainer) BuildNotifyNAS_IP4_ADDRESS(nasIPAddr string) {
	if nasIPAddr == "" {
		return
	} else {
		ipAddrByte := net.ParseIP(nasIPAddr).To4()
		container.BuildNotification(TypeNone, Vendor3GPPNotifyTypeNAS_IP4_ADDRESS, nil, ipAddrByte)
	}
}

func (container *IKEPayloadContainer) BuildNotifyUP_IP4_ADDRESS(upIPAddr string) {
	if upIPAddr == "" {
		return
	} else {
		ipAddrByte := net.ParseIP(upIPAddr).To4()
		container.BuildNotification(TypeNone, Vendor3GPPNotifyTypeUP_IP4_ADDRESS, nil, ipAddrByte)
	}
}

func (container *IKEPayloadContainer) BuildNotifyNAS_TCP_PORT(port uint16) {
	if port == 0 {
		return
	} else {
		portData := make([]byte, 2)
		binary.BigEndian.PutUint16(portData, port)
		container.BuildNotification(TypeNone, Vendor3GPPNotifyTypeNAS_TCP_PORT, nil, portData)
	}
}
