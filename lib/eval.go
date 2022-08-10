package lib

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/url"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

type CustomLib struct {
	envOptions     []cel.EnvOption
	programOptions []cel.ProgramOption
}

func NewEnv(c *CustomLib) (*cel.Env, error) {
	return cel.NewEnv(
		cel.Lib(c),
	)
}

func (c *CustomLib) CompileOptions() []cel.EnvOption {
	return c.envOptions
}

func (c *CustomLib) ProgramOptions() []cel.ProgramOption {
	return c.programOptions
}

func NewEnvOption() CustomLib {
	c := CustomLib{}

	c.envOptions = []cel.EnvOption{
		cel.Container("yamlctx"),
		cel.Declarations(
			// Custom functions
			decls.NewFunction("randomInt",
				decls.NewOverload("randomInt_int_int", []*exprpb.Type{decls.Int, decls.Int}, decls.Int)),
			decls.NewFunction("md5",
				decls.NewOverload("md5_string", []*exprpb.Type{decls.String}, decls.String)),
			decls.NewFunction("base64",
				decls.NewOverload("base64_string", []*exprpb.Type{decls.String}, decls.String)),
			decls.NewFunction("base64",
				decls.NewOverload("base64_bytes", []*exprpb.Type{decls.Bytes}, decls.String)),
			decls.NewFunction("base64Decode",
				decls.NewOverload("base64Decode_string", []*exprpb.Type{decls.String}, decls.String)),
			decls.NewFunction("base64Decode",
				decls.NewOverload("base64Decode_bytes", []*exprpb.Type{decls.Bytes}, decls.String)),
			decls.NewFunction("urlencode",
				decls.NewOverload("urlencode_string", []*exprpb.Type{decls.String}, decls.String)),
			decls.NewFunction("urlencode",
				decls.NewOverload("urlencode_bytes", []*exprpb.Type{decls.Bytes}, decls.String)),
			decls.NewFunction("urldecode",
				decls.NewOverload("urldecode_string", []*exprpb.Type{decls.String}, decls.String)),
			decls.NewFunction("urldecode",
				decls.NewOverload("urldecode_bytes", []*exprpb.Type{decls.Bytes}, decls.String)),
			decls.NewFunction("substr",
				decls.NewOverload("substr_string_int_int", []*exprpb.Type{decls.String, decls.Int, decls.Int}, decls.String)),
		),
	}

	c.programOptions = []cel.ProgramOption{
		cel.Functions(
			&functions.Overload{
				Operator: "randomInt_int_int",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					from, ok := lhs.(types.Int)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to randomInt", lhs.Type())
					}
					to, ok := rhs.(types.Int)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to randomInt", rhs.Type())
					}
					min, max := int(from), int(to)
					return types.Int(rand.Intn(max-min) + min)
				},
			},
			&functions.Overload{
				Operator: "md5_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to md5_string", value.Type())
					}
					return types.String(fmt.Sprintf("%x", md5.Sum([]byte(v))))
				},
			},
			&functions.Overload{
				Operator: "base64_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64_string", value.Type())
					}
					return types.String(base64.StdEncoding.EncodeToString([]byte(v)))
				},
			},
			&functions.Overload{
				Operator: "base64_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64_bytes", value.Type())
					}
					return types.String(base64.StdEncoding.EncodeToString(v))
				},
			},
			&functions.Overload{
				Operator: "base64Decode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_string", value.Type())
					}
					decodeBytes, err := base64.StdEncoding.DecodeString(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeBytes)
				},
			},
			&functions.Overload{
				Operator: "base64Decode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_bytes", value.Type())
					}
					decodeBytes, err := base64.StdEncoding.DecodeString(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeBytes)
				},
			},
			&functions.Overload{
				Operator: "urlencode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_string", value.Type())
					}
					return types.String(url.QueryEscape(string(v)))
				},
			},
			&functions.Overload{
				Operator: "urlencode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_bytes", value.Type())
					}
					return types.String(url.QueryEscape(string(v)))
				},
			},
			&functions.Overload{
				Operator: "urldecode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_string", value.Type())
					}
					decodeString, err := url.QueryUnescape(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeString)
				},
			},
			&functions.Overload{
				Operator: "urldecode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_bytes", value.Type())
					}
					decodeString, err := url.QueryUnescape(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeString)
				},
			},
			&functions.Overload{
				Operator: "substr_string_int_int",
				Function: func(values ...ref.Val) ref.Val {
					if len(values) == 3 {
						str, ok := values[0].(types.String)
						if !ok {
							return types.NewErr("invalid string to 'substr'")
						}
						start, ok := values[1].(types.Int)
						if !ok {
							return types.NewErr("invalid start to 'substr'")
						}
						length, ok := values[2].(types.Int)
						if !ok {
							return types.NewErr("invalid length to 'substr'")
						}
						runes := []rune(str)
						if start < 0 || length < 0 || int(start+length) > len(runes) {
							return types.NewErr("invalid start or length to 'substr'")
						}
						return types.String(runes[start : start+length])
					} else {
						return types.NewErr("too many arguments to 'substr'")
					}
				},
			},
		),
	}

	return c
}

// Refer to https://github.com/shadow1ng/fscan/blob/main/WebScan/lib/eval.go#L515
func (c *CustomLib) UpdateCompileOptions(args Sets) {
	for _, item := range args {
		k, v := item.Key, item.Value
		// 在执行之前是不知道变量的类型的，所以统一声明为字符型
		// 所以randomInt虽然返回的是int型，在运算中却被当作字符型进行计算，需要重载string_*_string
		var d *exprpb.Decl
		if strings.HasPrefix(v, "randomInt") {
			d = decls.NewConst(k, decls.Int, nil)
		} else {
			d = decls.NewConst(k, decls.String, nil)
		}

		c.envOptions = append(c.envOptions, cel.Declarations(d))
	}
}

func Evaluate(env *cel.Env, expression string, params map[string]interface{}) (ref.Val, error) {
	ast, iss := env.Compile(expression)
	if iss.Err() != nil {
		return nil, iss.Err()
	}

	prg, err := env.Program(ast)
	if err != nil {
		return nil, err
	}

	out, _, err := prg.Eval(params)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func EvalSets(sets *Sets, variableMap map[string]interface{}) error {
	c := NewEnvOption()
	c.UpdateCompileOptions(*sets)

	env, err := NewEnv(&c)
	if err != nil {
		fmt.Println(err)
	}

	for _, item := range *sets {
		k, expression := item.Key, item.Value
		out, _ := Evaluate(env, expression, variableMap)
		variableMap[k] = fmt.Sprintf("%v", out)
	}

	return err
}
