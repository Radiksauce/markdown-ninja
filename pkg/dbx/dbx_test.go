package dbx

import "testing"

func TestBuildQuery(t *testing.T) {
	tests := []struct {
		InitialQuery string
		BatchSize    int
		Arguments    [][]any
		Expected     string
	}{
		{
			"INSERT INTO table (a) VALUES",
			1,
			[][]any{{1}},
			"INSERT INTO table (a) VALUES ($1)",
		},
		{
			"INSERT INTO table (a) VALUES",
			1,
			[][]any{{1}, {2}},
			"INSERT INTO table (a) VALUES ($1),($2)",
		},
		{
			"INSERT INTO table (a) VALUES",
			1,
			[][]any{{1}, {2}, {3}},
			"INSERT INTO table (a) VALUES ($1),($2),($3)",
		},
		{
			"INSERT INTO table (a, b) VALUES",
			2,
			[][]any{{11, 12}, {21, 22}, {31, 32}},
			"INSERT INTO table (a, b) VALUES ($1,$2),($3,$4),($5,$6)",
		},
		{
			"INSERT INTO table (a, b, c) VALUES ",
			3,
			[][]any{{1, 2, 3}, {11, 12, 13}, {21, 22, 23}},
			"INSERT INTO table (a, b, c) VALUES ($1,$2,$3),($4,$5,$6),($7,$8,$9)",
		},
	}

	for _, test := range tests {
		queryBuilder := NewQueryBuilder(test.InitialQuery, len(test.Arguments), test.BatchSize)
		for _, item := range test.Arguments {
			queryBuilder.WriteValues(item...)
		}
		query := queryBuilder.Build()
		if query != test.Expected {
			t.Errorf("QueryBuilder: Expected: %s | Got: %s", test.Expected, query)
		}
	}

	for _, test := range tests {
		args := make([]any, 0, len(test.Arguments)*test.BatchSize)
		for _, item := range test.Arguments {
			args = append(args, item...)
		}

		query, err := BuildQuery(test.InitialQuery, test.BatchSize, args)
		if err != nil {
			t.Fatal(err)
		}
		if query != test.Expected {
			t.Errorf("BuildQuery Expected: %s | Got: %s", test.Expected, query)
		}
	}

}
