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
		cel.Function("randomInt",
			cel.Overload("randomInt_int_int", []*cel.Type{cel.IntType, cel.IntType}, cel.IntType,
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
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
				}),
			),
		),
		cel.Function("md5",
			cel.Overload("md5_string", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					val, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(val, "unexpected type '%v'", val.Type())
					}

					return types.String(fmt.Sprintf("%x", md5.Sum([]byte(val))))
				}),
			),
		),
		cel.Function("base64",
			cel.Overload("base64_string", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					val, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(val, "unexpected type '%v'", val.Type())
					}

					return types.String(base64.StdEncoding.EncodeToString([]byte(val)))
				}),
			),
		),
		cel.Function("base64",
			cel.Overload("base64_bytes", []*cel.Type{cel.BytesType}, cel.StringType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					val, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(val, "unexpected type '%v'", val.Type())
					}

					return types.String(base64.StdEncoding.EncodeToString(val))
				}),
			),
		),
		cel.Function("base64Decode",
			cel.Overload("base64Decode_string", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					val, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(val, "unexpected type '%v'", val.Type())
					}

					decodedBytes, err := base64.StdEncoding.DecodeString(string(val))
					if err != nil {
						return types.NewErr("%v", err)
					}

					return types.String(decodedBytes)
				}),
			),
		),
		cel.Function("base64Decode",
			cel.Overload("base64Decode_bytes", []*cel.Type{cel.BytesType}, cel.StringType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					val, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(val, "unexpected type '%v'", val.Type())
					}

					decodedBytes, err := base64.StdEncoding.DecodeString(string(val))
					if err != nil {
						return types.NewErr("%v", err)
					}

					return types.String(decodedBytes)
				}),
			),
		),
		cel.Function("urlencode",
			cel.Overload("urlencode_string", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					val, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(val, "unexpected type '%v'", val.Type())
					}

					return types.String(url.QueryEscape(string(val)))
				}),
			),
		),
		cel.Function("urlencode",
			cel.Overload("urlencode_bytes", []*cel.Type{cel.BytesType}, cel.StringType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					val, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(val, "unexpected type '%v'", val.Type())
					}

					return types.String(url.QueryEscape(string(val)))
				}),
			),
		),
		cel.Function("urldecode",
			cel.Overload("urldecode_string", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					val, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(val, "unexpected type '%v'", val.Type())
					}

					decodeString, err := url.QueryUnescape(string(val))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeString)
				}),
			),
		),
		cel.Function("urldecode",
			cel.Overload("urldecode_bytes", []*cel.Type{cel.BytesType}, cel.StringType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					val, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(val, "unexpected type '%v'", val.Type())
					}

					decodeString, err := url.QueryUnescape(string(val))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeString)
				}),
			),
		),
		cel.Function("substr",
			cel.Overload("substr_string_int_int", []*cel.Type{cel.StringType, cel.IntType, cel.IntType}, cel.StringType,
				cel.FunctionBinding(func(values ...ref.Val) ref.Val {
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
				}),
			),
		),
	}

	c.programOptions = []cel.ProgramOption{}

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
