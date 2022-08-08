package lib

import (
	"io/ioutil"

	"gopkg.in/yaml.v3"
)

type Poc struct {
	Name       string `yaml:"name"`
	Set        string `yaml:"set"`
	Rules      Rules  `yaml:"rules"`
	Expression string `yaml:"expressioin"`
	Detail     Detail `yaml:"detail"`
}

type Rules []RuleItem

type RuleItem struct {
	key  string
	rule Rule
}

func (r *Rules) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tmp1 yaml.MapSlice

	if err := unmarshal(&tmp1); err != nil {
		return err
	}
	var tmp = make(map[string][]Rules)
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	for _, one := range tmp1 {
		key := one.Key.(string)
		value := tmp[key]
		*r = append(*r, RuleItem{key, value})
	}
	return nil
}

type Rule struct {
	Request    Request `yaml:"request"`
	Expression string  `yaml:"expression"`
}

type Request struct {
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
}

type Detail struct {
	Author string   `yaml:"author"`
	Links  []string `yaml:"links"`
}

func LoadPoc(fileName string) (*Poc, error) {
	p := &Poc{}
	yamlFile, err := ioutil.ReadFile(fileName)

	err = yaml.Unmarshal(yamlFile, p)

	return p, err
}
