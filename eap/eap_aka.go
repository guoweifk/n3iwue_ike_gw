package eap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"

	"github.com/pkg/errors"
)

// Type definition for EAP-AKA (Type 23)

type EapAkaAttrType uint8

const (
	AKA_AT_RAND              EapAkaAttrType = 1
	AKA_AT_AUTN              EapAkaAttrType = 2
	AKA_AT_RES               EapAkaAttrType = 3
	AKA_AT_AUTS              EapAkaAttrType = 4
	AKA_AT_MAC               EapAkaAttrType = 11
	AKA_AT_NOTIFICATION      EapAkaAttrType = 12
	AKA_AT_ANY_ID_REQ        EapAkaAttrType = 13
	AKA_AT_IDENTITY          EapAkaAttrType = 14
	AKA_AT_CLIENT_ERROR_CODE EapAkaAttrType = 22
)

const (
	EAPAKASubTypeChallenge = 1
	EAPAKASubTypeIdentity  = 5
)

var _ EapTypeData = &EapAka{}

type EapAka struct {
	SubType    EapAkaSubtype
	Reserved   uint16
	Attributes map[EapAkaAttrType]*EapAkaAttr
}

type EapAkaAttr struct {
	AttrType            EapAkaAttrType
	Length              uint8
	Reserved            uint16
	Value               []byte
	Identity            string
	Identity_actual_len uint8
	Padding             string
}

func NewEapAka(subType EapAkaSubtype) *EapAka {
	return &EapAka{
		SubType:    subType,
		Attributes: make(map[EapAkaAttrType]*EapAkaAttr),
	}
}

func (eapAka *EapAka) Type() EapType { return EapTypeAKA }

func (eapAka *EapAka) SetAttr(attrType EapAkaAttrType, value []byte) error {
	if eapAka.Attributes == nil {
		eapAka.Attributes = make(map[EapAkaAttrType]*EapAkaAttr)
	}
	attr := new(EapAkaAttr)
	attr.AttrType = attrType
	attr.Value = make([]byte, len(value))
	copy(attr.Value, value)

	switch attrType {
	case AKA_AT_RAND, AKA_AT_AUTN, AKA_AT_MAC:
		if len(value) != 16 {
			return fmt.Errorf("attribute %v requires 16 bytes, got %d", attrType, len(value))
		}
		attr.Length = 5
	case AKA_AT_AUTS:
		if len(value) != 14 {
			return fmt.Errorf("attribute %v requires 14 bytes, got %d", attrType, len(value))
		}
		attr.Length = 4
	case AKA_AT_RES:
		bitLen := len(value) * 8
		if bitLen < 32 || bitLen > 128 {
			return fmt.Errorf("RES must be between 32 and 128 bits, got %d", bitLen)
		}
		attr.Reserved = uint16(bitLen)
		padding := (4 - (len(value)+4)%4) % 4
		attr.Length = uint8((len(value) + 4 + padding) / 4)
		padded := make([]byte, len(value)+padding)
		copy(padded, value)
		attr.Value = padded
	case AKA_AT_NOTIFICATION, AKA_AT_CLIENT_ERROR_CODE:
		if len(value) != 2 {
			return fmt.Errorf("attribute %v requires 2 bytes, got %d", attrType, len(value))
		}
		attr.Length = 1
		attr.Reserved = binary.BigEndian.Uint16(value)
		attr.Value = nil
	case AKA_AT_IDENTITY:
		attr.Length = uint8((len(value) + 4 + 3) / 4)
	default:
		return fmt.Errorf("unsupported attribute type: %v", attrType)
	}
	eapAka.Attributes[attrType] = attr
	return nil
}

func (eapAka *EapAka) GetAttr(attrType EapAkaAttrType) (EapAkaAttr, error) {
	if eapAka.Attributes == nil {
		return EapAkaAttr{}, errors.Errorf("EAP-AKA Attributes map is nil")
	}
	for _, attr := range eapAka.Attributes {
		if attr.AttrType == attrType {
			return *attr, nil
		}
	}
	return EapAkaAttr{}, errors.Errorf("EAP-AKA attribute[%d] not found", attrType)
}

// 这里是写结果的，其中Reserved，subType都是可以在这里写了
func (eapAka *EapAka) Marshal() ([]byte, error) {
	buffer := new(bytes.Buffer)
	buffer.WriteByte(byte(EapTypeAKA))
	buffer.WriteByte(byte(eapAka.SubType))
	binary.Write(buffer, binary.BigEndian, eapAka.Reserved)

	for _, key := range eapAka.getAttrsKeys() {
		attr := eapAka.Attributes[key]
		if err := binary.Write(buffer, binary.BigEndian, byte(attr.AttrType)); err != nil {
			return nil, err
		}

		if err := binary.Write(buffer, binary.BigEndian, attr.Length); err != nil {
			return nil, err
		}
		if attr.AttrType == AKA_AT_IDENTITY {
			// 写 2 字节大端的 Identity 实际长度（54 -> 0x00 0x36）
			if err := binary.Write(buffer, binary.BigEndian, uint16(len(attr.Identity))); err != nil {
				return nil, err
			}
			if _, err := buffer.Write([]byte(attr.Identity)); err != nil {
				return nil, err
			}
			// 写 Padding（把十六进制字符串转成字节再写，比如 "0000" -> 0x00 0x00）
			if attr.Padding != "" {
				p, err := hex.DecodeString(attr.Padding) // 需要：import "encoding/hex"
				if err != nil {
					return nil, err
				}
				if _, err := buffer.Write(p); err != nil {
					return nil, err
				}
			}
		}
		if err := binary.Write(buffer, binary.BigEndian, attr.Value); err != nil {
			return nil, err
		}
	}
	return buffer.Bytes(), nil
}

func (eapAka *EapAka) Unmarshal(rawData []byte) error {
	if len(rawData) < 4 {
		return errors.New("EAP-AKA Unmarshal(): insufficient bytes")
	}
	buf := bytes.NewReader(rawData)
	typeCode, _ := buf.ReadByte()
	if EapType(typeCode) != EapTypeAKA {
		return fmt.Errorf("unexpected EAP type: %d", typeCode)
	}
	subtype, _ := buf.ReadByte()
	eapAka.SubType = EapAkaSubtype(subtype)
	reserved := make([]byte, 2)
	io.ReadFull(buf, reserved)
	eapAka.Reserved = binary.BigEndian.Uint16(reserved)
	eapAka.Attributes = map[EapAkaAttrType]*EapAkaAttr{}

	for buf.Len() > 0 {
		// 读 Type / Length
		t, _ := buf.ReadByte()
		attrType := EapAkaAttrType(t)
		l, _ := buf.ReadByte()
		attr := &EapAkaAttr{AttrType: attrType, Length: l}

		totalLen := int(attr.Length) * 4

		// 读 Reserved（除 AUTS 外都有）
		consumed := 2 // 已消费：Type(1)+Length(1)
		if attrType != AKA_AT_AUTS {
			r := make([]byte, 2)
			if _, err := buf.Read(r); err != nil {
				return fmt.Errorf("read reserved failed: %w", err)
			}
			attr.Reserved = binary.BigEndian.Uint16(r)
			consumed += 2
		}

		// 计算 Value 长度
		valLen := totalLen - consumed

		// 按类型修正/校验
		switch attrType {
		case AKA_AT_RAND:
			// Length 应为 5，总 20；Value 应为 16B
			if valLen != 16 {
				return fmt.Errorf("AT_RAND: invalid value len=%d, want 16", valLen)
			}
		case AKA_AT_AUTN:
			if valLen != 16 {
				return fmt.Errorf("AT_AUTN: invalid value len=%d, want 16", valLen)
			}
		case AKA_AT_MAC:
			if valLen != 16 {
				return fmt.Errorf("AT_MAC: invalid value len=%d, want 16", valLen)
			}
		case AKA_AT_ANY_ID_REQ:
			// Length=1，总长=4，只读 Reserved，无 Value
			if attr.Reserved != 0 {
				return fmt.Errorf("AT_ANY_ID_REQ: reserved must be 0x0000, got 0x%04x", attr.Reserved)
			}
			valLen = 0
		default:
			// 其他类型保持原样
		}

		if valLen < 0 || valLen > buf.Len() {
			return fmt.Errorf("EAP-AKA Unmarshal(): invalid attribute length=%d for type=%v", attr.Length, attrType)
		}

		// 读 Value
		if valLen > 0 {
			attr.Value = make([]byte, valLen)
			if _, err := buf.Read(attr.Value); err != nil {
				return fmt.Errorf("read value failed: %w", err)
			}
		}

		eapAka.Attributes[attrType] = attr
	}
	return nil
}

func (eapAka *EapAka) initMAC() error {
	zeros := make([]byte, 16)
	return eapAka.SetAttr(AKA_AT_MAC, zeros)
}

func (eapAka *EapAka) getAttrsKeys() []EapAkaAttrType {
	result := make([]EapAkaAttrType, 0, len(eapAka.Attributes))
	for key := range eapAka.Attributes {
		result = append(result, key)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i] < result[j]
	})
	return result
}

// HMAC-SHA1 (128-bit truncated) for EAP-AKA
