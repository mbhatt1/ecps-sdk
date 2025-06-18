// Package serialization provides serialization and deserialization functionality for ECPS messages.
package serialization

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/ecps/ecps-go/pkg/core"
)

// ProtobufSerializer implements the Serializer interface for Protocol Buffers.
type ProtobufSerializer struct {
	preferJSON      bool
	messageTypeMap  map[string]reflect.Type
	jsonMarshaler   protojson.MarshalOptions
	jsonUnmarshaler protojson.UnmarshalOptions
}

// NewProtobufSerializer creates a new ProtobufSerializer.
func NewProtobufSerializer(preferJSON bool) *ProtobufSerializer {
	return &ProtobufSerializer{
		preferJSON:     preferJSON,
		messageTypeMap: make(map[string]reflect.Type),
		jsonMarshaler: protojson.MarshalOptions{
			UseProtoNames:   true,
			EmitUnpopulated: true,
		},
		jsonUnmarshaler: protojson.UnmarshalOptions{
			DiscardUnknown: true,
		},
	}
}

// RegisterMessageType registers a message type with its name.
func (s *ProtobufSerializer) RegisterMessageType(typeName string, messageType reflect.Type) {
	s.messageTypeMap[typeName] = messageType
}

// Serialize serializes a message to bytes.
func (s *ProtobufSerializer) Serialize(message interface{}, useJSON bool) ([]byte, error) {
	if message == nil {
		return nil, errors.New("cannot serialize nil message")
	}

	// Determine if we should use JSON
	useJSON = useJSON || s.preferJSON

	// Check if message is a proto.Message
	protoMsg, ok := message.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("message is not a proto.Message: %T", message)
	}

	if useJSON {
		// Use protojson for JSON serialization
		return s.jsonMarshaler.Marshal(protoMsg)
	}

	// Use proto.Marshal for binary serialization
	return proto.Marshal(protoMsg)
}

// Deserialize deserializes bytes to a message.
func (s *ProtobufSerializer) Deserialize(data []byte, messageType interface{}, useJSON bool) (interface{}, error) {
	if data == nil || len(data) == 0 {
		return nil, errors.New("cannot deserialize empty data")
	}

	// Determine if we should use JSON
	useJSON = useJSON || s.preferJSON

	// Handle messageType as string (type name)
	if typeName, ok := messageType.(string); ok {
		msgType, ok := s.messageTypeMap[typeName]
		if !ok {
			return nil, fmt.Errorf("unknown message type name: %s", typeName)
		}
		messageType = reflect.New(msgType.Elem()).Interface()
	}

	// Check if messageType is a proto.Message
	protoMsg, ok := messageType.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("messageType is not a proto.Message: %T", messageType)
	}

	// Create a new instance of the message type
	msg := proto.Clone(protoMsg)

	if useJSON {
		// Use protojson for JSON deserialization
		if err := s.jsonUnmarshaler.Unmarshal(data, msg); err != nil {
			return nil, err
		}
	} else {
		// Use proto.Unmarshal for binary deserialization
		if err := proto.Unmarshal(data, msg); err != nil {
			return nil, err
		}
	}

	return msg, nil
}

// GetMessageTypeName returns the type name of a message.
func (s *ProtobufSerializer) GetMessageTypeName(message interface{}) string {
	if message == nil {
		return ""
	}

	// Check if message is a proto.Message
	if protoMsg, ok := message.(proto.Message); ok {
		return string(protoMsg.ProtoReflect().Descriptor().FullName())
	}

	// Fallback to Go type name
	return reflect.TypeOf(message).String()
}

// IsValidMessage checks if an object is a valid Protocol Buffers message.
func (s *ProtobufSerializer) IsValidMessage(message interface{}) bool {
	if message == nil {
		return false
	}

	_, ok := message.(proto.Message)
	return ok
}

// PackAny packs a message into an Any.
func (s *ProtobufSerializer) PackAny(message proto.Message) (*anypb.Any, error) {
	if message == nil {
		return nil, errors.New("cannot pack nil message")
	}

	return anypb.New(message)
}

// UnpackAny unpacks a message from an Any.
func (s *ProtobufSerializer) UnpackAny(any *anypb.Any, target proto.Message) error {
	if any == nil {
		return errors.New("cannot unpack nil Any")
	}
	if target == nil {
		return errors.New("cannot unpack to nil target")
	}

	return any.UnmarshalTo(target)
}

// ConvertJSONToBytes converts a JSON string to bytes.
func (s *ProtobufSerializer) ConvertJSONToBytes(jsonStr string) ([]byte, error) {
	if jsonStr == "" {
		return nil, nil
	}
	return []byte(jsonStr), nil
}

// ConvertBytesToJSON converts bytes to a JSON string.
func (s *ProtobufSerializer) ConvertBytesToJSON(data []byte) (string, error) {
	if data == nil || len(data) == 0 {
		return "", nil
	}
	return string(data), nil
}

// MarshalJSON marshals a Go object to JSON bytes.
func (s *ProtobufSerializer) MarshalJSON(obj interface{}) ([]byte, error) {
	if obj == nil {
		return nil, errors.New("cannot marshal nil object")
	}

	// Check if object is a proto.Message
	if protoMsg, ok := obj.(proto.Message); ok {
		// Use protojson for proto.Message
		return s.jsonMarshaler.Marshal(protoMsg)
	}

	// Use standard json package for other types
	return json.Marshal(obj)
}

// UnmarshalJSON unmarshals JSON bytes to a Go object.
func (s *ProtobufSerializer) UnmarshalJSON(data []byte, obj interface{}) error {
	if data == nil || len(data) == 0 {
		return errors.New("cannot unmarshal empty data")
	}
	if obj == nil {
		return errors.New("cannot unmarshal to nil object")
	}

	// Check if object is a proto.Message
	if protoMsg, ok := obj.(proto.Message); ok {
		// Use protojson for proto.Message
		return s.jsonUnmarshaler.Unmarshal(data, protoMsg)
	}

	// Use standard json package for other types
	return json.Unmarshal(data, obj)
}

// GetField gets a field value from a message using reflection.
func (s *ProtobufSerializer) GetField(message proto.Message, fieldName string) (interface{}, error) {
	if message == nil {
		return nil, errors.New("cannot get field from nil message")
	}

	// Use protoreflect to access fields
	msg := message.ProtoReflect()
	fields := msg.Descriptor().Fields()
	field := fields.ByName(protoreflect.Name(fieldName))
	if field == nil {
		return nil, fmt.Errorf("field not found: %s", fieldName)
	}

	// Get field value
	value := msg.Get(field)
	return s.convertProtoValue(value, field), nil
}

// SetField sets a field value in a message using reflection.
func (s *ProtobufSerializer) SetField(message proto.Message, fieldName string, fieldValue interface{}) error {
	if message == nil {
		return errors.New("cannot set field in nil message")
	}

	// Use protoreflect to access fields
	msg := message.ProtoReflect()
	fields := msg.Descriptor().Fields()
	field := fields.ByName(protoreflect.Name(fieldName))
	if field == nil {
		return fmt.Errorf("field not found: %s", fieldName)
	}

	// Convert Go value to protoreflect.Value
	value, err := s.convertGoValue(fieldValue, field)
	if err != nil {
		return err
	}

	// Set field value
	msg.Set(field, value)
	return nil
}

// Helper function to convert protoreflect.Value to Go value
func (s *ProtobufSerializer) convertProtoValue(value protoreflect.Value, field protoreflect.FieldDescriptor) interface{} {
	switch field.Kind() {
	case protoreflect.BoolKind:
		return value.Bool()
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return int32(value.Int())
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return value.Int()
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return uint32(value.Uint())
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return value.Uint()
	case protoreflect.FloatKind:
		return float32(value.Float())
	case protoreflect.DoubleKind:
		return value.Float()
	case protoreflect.StringKind:
		return value.String()
	case protoreflect.BytesKind:
		return value.Bytes()
	case protoreflect.EnumKind:
		return value.Enum()
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return value.Message().Interface()
	default:
		return nil
	}
}

// Helper function to convert Go value to protoreflect.Value
func (s *ProtobufSerializer) convertGoValue(value interface{}, field protoreflect.FieldDescriptor) (protoreflect.Value, error) {
	switch field.Kind() {
	case protoreflect.BoolKind:
		if v, ok := value.(bool); ok {
			return protoreflect.ValueOfBool(v), nil
		}
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		if v, ok := value.(int32); ok {
			return protoreflect.ValueOfInt64(int64(v)), nil
		}
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		if v, ok := value.(int64); ok {
			return protoreflect.ValueOfInt64(v), nil
		}
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		if v, ok := value.(uint32); ok {
			return protoreflect.ValueOfUint64(uint64(v)), nil
		}
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		if v, ok := value.(uint64); ok {
			return protoreflect.ValueOfUint64(v), nil
		}
	case protoreflect.FloatKind:
		if v, ok := value.(float32); ok {
			return protoreflect.ValueOfFloat32(v), nil
		}
	case protoreflect.DoubleKind:
		if v, ok := value.(float64); ok {
			return protoreflect.ValueOfFloat64(v), nil
		}
	case protoreflect.StringKind:
		if v, ok := value.(string); ok {
			return protoreflect.ValueOfString(v), nil
		}
	case protoreflect.BytesKind:
		if v, ok := value.([]byte); ok {
			return protoreflect.ValueOfBytes(v), nil
		}
	case protoreflect.EnumKind:
		if v, ok := value.(int32); ok {
			return protoreflect.ValueOfEnum(protoreflect.EnumNumber(v)), nil
		}
	case protoreflect.MessageKind, protoreflect.GroupKind:
		if v, ok := value.(proto.Message); ok {
			return protoreflect.ValueOfMessage(v.ProtoReflect()), nil
		}
	}

	return protoreflect.Value{}, fmt.Errorf("cannot convert %T to %s", value, field.Kind())
}