package queryshape

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gopkg.in/mgo.v2/bson"
)

func TestQueryShape(t *testing.T) {
	testCases := []struct {
		in  bson.M
		out string
	}{
		{
			bson.M{"find": "c0", "filter": bson.M{"rating": bson.M{"$gte": 9}, "cuisine": "italian"}},
			`{"filter":{"cuisine":1,"rating":{"$gte":1}},"find":1}`,
		},
		{
			bson.M{"": "value"},
			`{"":1}`,
		},
	}
	for _, tc := range testCases {
		assert.Equal(t, tc.out, GetQueryShape(tc.in))
	}
}
