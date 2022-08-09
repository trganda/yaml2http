package lib

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v3"
)

type Poc struct {
	Name       string `yaml:"name"`
	Set        string `yaml:"set"`
	Rules      Rules  `yaml:"rules"`
	Expression string `yaml:"expression"`
	Detail     Detail `yaml:"detail"`
}

type Rules []RuleItem

type RuleItem struct {
	key  string
	rule Rule
}

func (r *Rules) UnmarshalYAML(unmarshal func(interface{}) error) error {

	var tmp = make(map[string]Rule)
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	for key, value := range tmp {
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
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, p)

	return p, err
}
