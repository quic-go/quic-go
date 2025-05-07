package gojay

type testObject struct {
	testStr         string
	testStrNull     *string
	testInt         int
	testIntNull     *int
	testInt64       int64
	testInt64Null   *int64
	testInt32       int32
	testInt32Null   *int32
	testInt16       int16
	testInt16Null   *int16
	testInt8        int8
	testInt8Null    *int8
	testUint64      uint64
	testUint64Null  *uint64
	testUint32      uint32
	testUint32Null  *uint32
	testUint16      uint16
	testUint16Null  *uint16
	testUint8       uint8
	testUint8Null   *uint8
	testFloat64     float64
	testFloat64Null *float64
	testFloat32     float32
	testFloat32Null *float32
	testBool        bool
	testBoolNull    *bool
	testSubObject   *testObject
	testSubArray    testSliceInts
	testInterface   interface{}
}

// make sure it implements interfaces
var _ MarshalerJSONObject = &testObject{}
var _ UnmarshalerJSONObject = &testObject{}

func (t *testObject) IsNil() bool {
	return t == nil
}

func (t *testObject) MarshalJSONObject(enc *Encoder) {
	enc.AddStringKey("testStr", t.testStr)
	enc.AddIntKey("testInt", t.testInt)
	enc.AddIntKey("testInt64", int(t.testInt64))
	enc.AddIntKey("testInt32", int(t.testInt32))
	enc.AddIntKey("testInt16", int(t.testInt16))
	enc.AddIntKey("testInt8", int(t.testInt8))
	enc.AddIntKey("testUint64", int(t.testUint64))
	enc.AddIntKey("testUint32", int(t.testUint32))
	enc.AddIntKey("testUint16", int(t.testUint16))
	enc.AddIntKey("testUint8", int(t.testUint8))
	enc.AddFloatKey("testFloat64", t.testFloat64)
	enc.AddFloat32Key("testFloat32", t.testFloat32)
	enc.AddBoolKey("testBool", t.testBool)
}

func (t *testObject) UnmarshalJSONObject(dec *Decoder, k string) error {
	switch k {
	case "testStr":
		return dec.AddString(&t.testStr)
	case "testStrNull":
		return dec.AddStringNull(&t.testStrNull)
	case "testInt":
		return dec.AddInt(&t.testInt)
	case "testIntNull":
		return dec.AddIntNull(&t.testIntNull)
	case "testInt64":
		return dec.AddInt64(&t.testInt64)
	case "testInt64Null":
		return dec.AddInt64Null(&t.testInt64Null)
	case "testInt32":
		return dec.AddInt32(&t.testInt32)
	case "testInt32Null":
		return dec.AddInt32Null(&t.testInt32Null)
	case "testInt16":
		return dec.AddInt16(&t.testInt16)
	case "testInt16Null":
		return dec.AddInt16Null(&t.testInt16Null)
	case "testInt8":
		return dec.AddInt8(&t.testInt8)
	case "testInt8Null":
		return dec.AddInt8Null(&t.testInt8Null)
	case "testUint64":
		return dec.AddUint64(&t.testUint64)
	case "testUint64Null":
		return dec.AddUint64Null(&t.testUint64Null)
	case "testUint32":
		return dec.AddUint32(&t.testUint32)
	case "testUint32Null":
		return dec.AddUint32Null(&t.testUint32Null)
	case "testUint16":
		return dec.AddUint16(&t.testUint16)
	case "testUint16Null":
		return dec.AddUint16Null(&t.testUint16Null)
	case "testUint8":
		return dec.AddUint8(&t.testUint8)
	case "testUint8Null":
		return dec.AddUint8Null(&t.testUint8Null)
	case "testFloat64":
		return dec.AddFloat(&t.testFloat64)
	case "testFloat64Null":
		return dec.AddFloatNull(&t.testFloat64Null)
	case "testFloat32":
		return dec.AddFloat32(&t.testFloat32)
	case "testFloat32Null":
		return dec.AddFloat32Null(&t.testFloat32Null)
	case "testBool":
		return dec.AddBool(&t.testBool)
	case "testBoolNull":
		return dec.AddBoolNull(&t.testBoolNull)
	case "testInterface":
		return dec.AddInterface(&t.testInterface)
	}
	return nil
}

func (t *testObject) NKeys() int {
	return 29
}

type testObject0Keys struct {
	testStr       string
	testInt       int
	testInt64     int64
	testInt32     int32
	testInt16     int16
	testInt8      int8
	testUint64    uint64
	testUint32    uint32
	testUint16    uint16
	testUint8     uint8
	testFloat64   float64
	testFloat32   float32
	testBool      bool
	testSubObject *testObject0Keys
	testSubArray  testSliceInts
	testInterface interface{}
}

// make sure it implements interfaces
var _ MarshalerJSONObject = &testObject0Keys{}
var _ UnmarshalerJSONObject = &testObject0Keys{}

func (t *testObject0Keys) IsNil() bool {
	return t == nil
}

func (t *testObject0Keys) MarshalJSONObject(enc *Encoder) {
	enc.AddStringKey("testStr", t.testStr)
	enc.AddIntKey("testInt", t.testInt)
	enc.AddIntKey("testInt64", int(t.testInt64))
	enc.AddIntKey("testInt32", int(t.testInt32))
	enc.AddIntKey("testInt16", int(t.testInt16))
	enc.AddIntKey("testInt8", int(t.testInt8))
	enc.AddIntKey("testUint64", int(t.testUint64))
	enc.AddIntKey("testUint32", int(t.testUint32))
	enc.AddIntKey("testUint16", int(t.testUint16))
	enc.AddIntKey("testUint8", int(t.testUint8))
	enc.AddFloatKey("testFloat64", t.testFloat64)
	enc.AddFloat32Key("testFloat32", t.testFloat32)
	enc.AddBoolKey("testBool", t.testBool)
	enc.AddInterfaceKey("testInterface", t.testInterface)
}

func (t *testObject0Keys) UnmarshalJSONObject(dec *Decoder, k string) error {
	switch k {
	case "testStr":
		return dec.AddString(&t.testStr)
	case "testInt":
		return dec.AddInt(&t.testInt)
	case "testInt64":
		return dec.AddInt64(&t.testInt64)
	case "testInt32":
		return dec.AddInt32(&t.testInt32)
	case "testInt16":
		return dec.AddInt16(&t.testInt16)
	case "testInt8":
		return dec.AddInt8(&t.testInt8)
	case "testUint64":
		return dec.AddUint64(&t.testUint64)
	case "testUint32":
		return dec.AddUint32(&t.testUint32)
	case "testUint16":
		return dec.AddUint16(&t.testUint16)
	case "testUint8":
		return dec.AddUint8(&t.testUint8)
	case "testFloat64":
		return dec.AddFloat(&t.testFloat64)
	case "testFloat32":
		return dec.AddFloat32(&t.testFloat32)
	case "testBool":
		return dec.AddBool(&t.testBool)
	case "testInterface":
		return dec.AddInterface(&t.testInterface)
	}
	return nil
}

func (t *testObject0Keys) NKeys() int {
	return 0
}

type testObjectComplex struct {
	testSubObject    *testObject
	testSubSliceInts *testSliceInts
	testStr          string
	testSubObject2   *testObjectComplex
}

func (t *testObjectComplex) IsNil() bool {
	return t == nil
}

func (t *testObjectComplex) MarshalJSONObject(enc *Encoder) {
	enc.AddObjectKey("testSubObject", t.testSubObject)
	enc.AddStringKey("testStr", t.testStr)
	enc.AddObjectKey("testStr", t.testSubObject2)
}

func (t *testObjectComplex) UnmarshalJSONObject(dec *Decoder, k string) error {
	switch k {
	case "testSubObject":
		return dec.AddObject(t.testSubObject)
	case "testSubSliceInts":
		return dec.AddArray(t.testSubSliceInts)
	case "testStr":
		return dec.AddString(&t.testStr)
	case "testSubObject2":
		return dec.AddObject(t.testSubObject2)
	}
	return nil
}

func (t *testObjectComplex) NKeys() int {
	return 4
}

// make sure it implements interfaces
var _ MarshalerJSONObject = &testObjectComplex{}
var _ UnmarshalerJSONObject = &testObjectComplex{}

type TestObj struct {
	test        int
	test2       int
	test3       string
	test4       string
	test5       float64
	testArr     testSliceObjects
	testSubObj  *TestSubObj
	testSubObj2 *TestSubObj
}

type TestSubObj struct {
	test3          int
	test4          int
	test5          string
	testSubSubObj  *TestSubObj
	testSubSubObj2 *TestSubObj
}

func (t *TestSubObj) UnmarshalJSONObject(dec *Decoder, key string) error {
	switch key {
	case "test":
		return dec.AddInt(&t.test3)
	case "test2":
		return dec.AddInt(&t.test4)
	case "test3":
		return dec.AddString(&t.test5)
	case "testSubSubObj":
		t.testSubSubObj = &TestSubObj{}
		return dec.AddObject(t.testSubSubObj)
	case "testSubSubObj2":
		t.testSubSubObj2 = &TestSubObj{}
		return dec.AddObject(t.testSubSubObj2)
	}
	return nil
}

func (t *TestSubObj) NKeys() int {
	return 0
}

func (t *TestObj) UnmarshalJSONObject(dec *Decoder, key string) error {
	switch key {
	case "test":
		return dec.AddInt(&t.test)
	case "test2":
		return dec.AddInt(&t.test2)
	case "test3":
		return dec.AddString(&t.test3)
	case "test4":
		return dec.AddString(&t.test4)
	case "test5":
		return dec.AddFloat(&t.test5)
	case "testSubObj":
		t.testSubObj = &TestSubObj{}
		return dec.AddObject(t.testSubObj)
	case "testSubObj2":
		t.testSubObj2 = &TestSubObj{}
		return dec.AddObject(t.testSubObj2)
	case "testArr":
		return dec.AddArray(&t.testArr)
	}
	return nil
}

func (t *TestObj) NKeys() int {
	return 8
}
