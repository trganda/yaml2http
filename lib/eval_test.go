package lib_test

import (
	"fmt"
	"reflect"
	"testing"

	"trganda.com/yaml2http/lib"
)

func TestRandomInt(t *testing.T) {
	c := lib.NewEnvOption()
	env, _ := lib.NewEnv(&c)
	ast, _ := env.Compile(`randomInt(100, 200)`)
	prg, _ := env.Program(ast)

	variableMap := make(map[string]interface{})
	defer func() {
		variableMap = nil
	}()

	out, _, _ := prg.Eval(variableMap)

	if out.Type().TypeName() == "int" {
		t.Logf("%v", out)
	}
}

func TestMd5(t *testing.T) {
	c := lib.NewEnvOption()
	env, _ := lib.NewEnv(&c)

	want := "33e78d60bc1f9dcc7291c891e6f069e4"

	variableMap := make(map[string]interface{})
	defer func() {
		variableMap = nil
	}()

	out, _ := lib.Evaluate(env, `md5("dsfsdf")`, variableMap)
	outs := fmt.Sprintf("%v", out)

	if !reflect.DeepEqual(outs, want) {
		t.Fatalf("no expected got: %v want: %v\n", outs, want)
	}
}

func TestBase64String(t *testing.T) {
	c := lib.NewEnvOption()
	env, _ := lib.NewEnv(&c)

	want := "ZHNmc2Rm"

	variableMap := make(map[string]interface{})
	defer func() {
		variableMap = nil
	}()

	out, _ := lib.Evaluate(env, `base64("dsfsdf")`, variableMap)
	outs := fmt.Sprintf("%v", out)

	if !reflect.DeepEqual(outs, want) {
		t.Fatalf("no expected got: %v want: %v\n", outs, want)
	}
}

func TestBase64SBytes(t *testing.T) {
	c := lib.NewEnvOption()
	env, _ := lib.NewEnv(&c)

	want := "ZHNmc2Rm"

	variableMap := make(map[string]interface{})
	defer func() {
		variableMap = nil
	}()

	out, _ := lib.Evaluate(env, `base64(b"dsfsdf")`, variableMap)
	outs := fmt.Sprintf("%v", out)

	if !reflect.DeepEqual(outs, want) {
		t.Fatalf("no expected got: %v want: %v\n", outs, want)
	}
}

func TestBase64DecodeString(t *testing.T) {
	c := lib.NewEnvOption()
	env, _ := lib.NewEnv(&c)

	want := "dsfsdf"

	variableMap := make(map[string]interface{})
	defer func() {
		variableMap = nil
	}()

	out, _ := lib.Evaluate(env, `base64Decode("ZHNmc2Rm")`, variableMap)
	outs := fmt.Sprintf("%v", out)

	if !reflect.DeepEqual(outs, want) {
		t.Fatalf("no expected got: %v want: %v\n", outs, want)
	}
}

func TestBase64DecodeBytes(t *testing.T) {
	c := lib.NewEnvOption()
	env, _ := lib.NewEnv(&c)

	want := "dsfsdf"

	variableMap := make(map[string]interface{})
	defer func() {
		variableMap = nil
	}()

	out, _ := lib.Evaluate(env, `base64Decode(b"ZHNmc2Rm")`, variableMap)
	outs := fmt.Sprintf("%v", out)

	if !reflect.DeepEqual(outs, want) {
		t.Fatalf("no expected got: %v want: %v\n", outs, want)
	}
}

func TestUrlEncodeString(t *testing.T) {
	c := lib.NewEnvOption()
	env, _ := lib.NewEnv(&c)

	want := "%26%3F%3D"

	variableMap := make(map[string]interface{})
	defer func() {
		variableMap = nil
	}()

	out, _ := lib.Evaluate(env, `urlencode("&?=")`, variableMap)
	outs := fmt.Sprintf("%v", out)

	if !reflect.DeepEqual(outs, want) {
		t.Fatalf("no expected got: %v want: %v\n", outs, want)
	}
}

func TestUrlEncodeBytes(t *testing.T) {
	c := lib.NewEnvOption()
	env, _ := lib.NewEnv(&c)

	want := "%26%3F%3D"

	variableMap := make(map[string]interface{})
	defer func() {
		variableMap = nil
	}()

	out, _ := lib.Evaluate(env, `urlencode(b"&?=")`, variableMap)
	outs := fmt.Sprintf("%v", out)

	if !reflect.DeepEqual(outs, want) {
		t.Fatalf("no expected got: %v want: %v\n", outs, want)
	}
}

func TestUrlDecodeString(t *testing.T) {
	c := lib.NewEnvOption()
	env, _ := lib.NewEnv(&c)

	want := "&?="

	variableMap := make(map[string]interface{})
	defer func() {
		variableMap = nil
	}()

	out, _ := lib.Evaluate(env, `urldecode("%26%3F%3D")`, variableMap)
	outs := fmt.Sprintf("%v", out)

	if !reflect.DeepEqual(outs, want) {
		t.Fatalf("no expected got: %v want: %v\n", outs, want)
	}
}

func TestUrlDecodeBytes(t *testing.T) {
	c := lib.NewEnvOption()
	env, _ := lib.NewEnv(&c)

	want := "&?="

	variableMap := make(map[string]interface{})
	defer func() {
		variableMap = nil
	}()

	out, _ := lib.Evaluate(env, `urldecode(b"%26%3F%3D")`, variableMap)
	outs := fmt.Sprintf("%v", out)

	if !reflect.DeepEqual(outs, want) {
		t.Fatalf("no expected got: %v want: %v\n", outs, want)
	}
}

func TestSubstr(t *testing.T) {
	c := lib.NewEnvOption()
	env, _ := lib.NewEnv(&c)

	want := "ds"

	variableMap := make(map[string]interface{})
	defer func() {
		variableMap = nil
	}()

	out, _ := lib.Evaluate(env, `substr("dsfsdf", 0, 2)`, variableMap)
	outs := fmt.Sprintf("%v", out)

	if !reflect.DeepEqual(outs, want) {
		t.Fatalf("no expected got: %v want: %v\n", outs, want)
	}
}
