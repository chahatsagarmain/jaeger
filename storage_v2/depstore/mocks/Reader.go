// Copyright (c) The Jaeger Authors.
// SPDX-License-Identifier: Apache-2.0
//
// Run 'make generate-mocks' to regenerate.

// Code generated by mockery. DO NOT EDIT.

package mocks

import (
	context "context"

	depstore "github.com/jaegertracing/jaeger/storage_v2/depstore"
	mock "github.com/stretchr/testify/mock"

	model "github.com/jaegertracing/jaeger/model"
)

// Reader is an autogenerated mock type for the Reader type
type Reader struct {
	mock.Mock
}

// GetDependencies provides a mock function with given fields: ctx, query
func (_m *Reader) GetDependencies(ctx context.Context, query depstore.QueryParameters) ([]model.DependencyLink, error) {
	ret := _m.Called(ctx, query)

	if len(ret) == 0 {
		panic("no return value specified for GetDependencies")
	}

	var r0 []model.DependencyLink
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, depstore.QueryParameters) ([]model.DependencyLink, error)); ok {
		return rf(ctx, query)
	}
	if rf, ok := ret.Get(0).(func(context.Context, depstore.QueryParameters) []model.DependencyLink); ok {
		r0 = rf(ctx, query)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.DependencyLink)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, depstore.QueryParameters) error); ok {
		r1 = rf(ctx, query)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewReader creates a new instance of Reader. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewReader(t interface {
	mock.TestingT
	Cleanup(func())
}) *Reader {
	mock := &Reader{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
