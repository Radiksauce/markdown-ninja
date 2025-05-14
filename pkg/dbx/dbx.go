package dbx

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
)

// The maximum number of arguments of a query.
// See https://www.postgresql.org/docs/current/limits.html
// const POSTGRES_MAX_QUERY_PARAMS = 65_535 - 1

type QueryBuilder struct {
	queryBuilder *strings.Builder
	valuesCount  int
}

type Nullable[T driver.Valuer] struct {
	value *T
}

func NewNullable[T driver.Valuer](value *T) Nullable[T] {
	return Nullable[T]{value: value}
}

func (opt Nullable[T]) Value() (driver.Value, error) {
	if opt.value == nil {
		return nil, nil
	}
	return (*opt.value).Value()
}

func NewQueryBuilder(initialQuery string, numberOfItems int, numberOfValuesPerItem int) QueryBuilder {
	queryBuilder := &strings.Builder{}
	queryBuilder.Grow((numberOfItems*numberOfValuesPerItem)*5 + 2)

	queryBuilder.WriteString(initialQuery)
	if !strings.HasSuffix(initialQuery, " ") {
		queryBuilder.WriteRune(' ')
	}

	return QueryBuilder{
		valuesCount:  1,
		queryBuilder: queryBuilder,
	}
}

func (builder *QueryBuilder) WriteValues(values ...any) {
	if builder.valuesCount != 1 {
		builder.queryBuilder.WriteRune(',')
	}

	builder.queryBuilder.WriteRune('(')

	numberofValues := len(values)
	for i := range values {
		builder.queryBuilder.WriteString(fmt.Sprintf("$%d", builder.valuesCount))
		builder.valuesCount += 1
		if i == numberofValues-1 {
			builder.queryBuilder.WriteRune(')')
		} else {
			builder.queryBuilder.WriteRune(',')
		}
	}
}

func (builder *QueryBuilder) Build() string {
	return builder.queryBuilder.String()
}

func BuildQuery(initialQuery string, batchSize int, arguments []any) (query string, err error) {
	argsLen := len(arguments)

	if argsLen%batchSize != 0 {
		return "", errors.New("BuildQuery: len(arguments) %% batchSize != 0")
	}

	queryBuilder := strings.Builder{}
	queryBuilder.Grow(len(arguments)*5 + 2)

	queryBuilder.WriteString(initialQuery)
	if !strings.HasSuffix(initialQuery, " ") {
		queryBuilder.WriteRune(' ')
	}
	queryBuilder.WriteRune('(')

	for i := 1; i <= argsLen; i += 1 {
		queryBuilder.WriteString(fmt.Sprintf("$%d", i))

		if i%batchSize == 0 {
			if i == argsLen {
				queryBuilder.WriteRune(')')
			} else {
				queryBuilder.WriteString("),(")

			}
		} else {
			queryBuilder.WriteString(",")
		}
	}

	return queryBuilder.String(), nil
}
