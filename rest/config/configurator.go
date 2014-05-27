package config

import (
	"errors"
	"net/http"
)

var (
	ErrNoProvider = errors.New("auth: no provider found")
)

type ConfiguratorProvider interface {
	OpenConfigurator(*http.Request) (Configurator, error)
}

type Configurator interface {
	Set(key, val string) error
	Get(key string) (string, error)
	Close() error
}

var (
	mapProvider  = make(map[string]ConfiguratorProvider)
	lastProvider ConfiguratorProvider
)

func ConfiguratorRegister(name string, c ConfiguratorProvider) error {
	_, ok := mapProvider[name]
	if ok {
		return ErrNoProvider
	}

	mapProvider[name] = c
	lastProvider = c
	return nil
}

func GetProvider(name string) (ConfiguratorProvider, error) {
	p, ok := mapProvider[name]
	if !ok {
		return nil, ErrNoProvider
	}

	return p, nil
}

// Provider returns the last provider added. It will panic if there's no one.
func Provider() ConfiguratorProvider {
	if lastProvider == nil {
		panic(ErrNoProvider.Error())
	}
	return lastProvider
}
