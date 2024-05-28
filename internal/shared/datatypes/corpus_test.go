package datatypes

import (
	"reflect"
	"testing"
)

func TestSplitParameterString(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{
			input: "foo-bar",
			want:  []string{"foo", "bar"},
		},
		{
			input: "foo_bar",
			want:  []string{"foo", "bar"},
		},
		{
			input: "foobar",
			want:  []string{"foobar"},
		},
		{
			input: "foo-bar_1-2-3_abcdef",
			want:  []string{"foo", "bar", "abcdef"},
		},
		{
			input: "areallylongparameterstringthatismorethanfiftycharacters",
			want:  []string{},
		},
		{
			input: "123-456",
			want:  []string{},
		},
	}

	for _, test := range tests {
		got := splitParameterString(test.input)
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("splitParameterString(%q) = %v, want %v", test.input, got, test.want)
		}
	}
}

func TestSplitPathString(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{
			input: "/foo/bar",
			want:  []string{"foo", "bar"},
		},
		{
			input: "/foo_bar",
			want:  []string{"foo", "bar"},
		},
		{
			input: "/foobar",
			want:  []string{"foobar"},
		},
		{
			input: "/foo-bar_1-2-3_abcdef",
			want:  []string{"foo", "bar", "abcdef"},
		},
		{
			input: "/areallylongpathsegmentthatismorethanfiftycharacters",
			want:  []string{},
		},
		{
			input: "/123-456",
			want:  []string{},
		},
		{
			input: "",
			want:  []string{},
		},
		{
			input: "/",
			want:  []string{},
		},
	}

	for _, test := range tests {
		got := splitPathString(test.input)
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("splitPathString(%q) = %v, want %v", test.input, got, test.want)
		}
	}
}
