package protocol

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidVersion(t *testing.T) {
	require.False(t, IsValidVersion(VersionUnknown))
	require.False(t, IsValidVersion(versionDraft29))
	require.True(t, IsValidVersion(Version1))
	require.True(t, IsValidVersion(Version2))
	require.False(t, IsValidVersion(1234))
}

func TestVersionStringRepresentation(t *testing.T) {
	require.Equal(t, "unknown", VersionUnknown.String())
	require.Equal(t, "draft-29", versionDraft29.String())
	require.Equal(t, "v1", Version1.String())
	require.Equal(t, "v2", Version2.String())
	// check with unsupported version numbers from the wiki
	require.Equal(t, "gQUIC 9", Version(0x51303039).String())
	require.Equal(t, "gQUIC 13", Version(0x51303133).String())
	require.Equal(t, "gQUIC 25", Version(0x51303235).String())
	require.Equal(t, "gQUIC 48", Version(0x51303438).String())
	require.Equal(t, "0x1234567", Version(0x01234567).String())
}

func TestRecognizesSupportedVersions(t *testing.T) {
	require.False(t, IsSupportedVersion(SupportedVersions, 0))
	require.False(t, IsSupportedVersion(SupportedVersions, maxGquicVersion))
	require.True(t, IsSupportedVersion(SupportedVersions, SupportedVersions[0]))
	require.True(t, IsSupportedVersion(SupportedVersions, SupportedVersions[len(SupportedVersions)-1]))
}

func TestVersionSelection(t *testing.T) {
	tests := []struct {
		name              string
		supportedVersions []Version
		otherVersions     []Version
		expectedVersion   Version
		expectedOK        bool
	}{
		{
			name:              "finds matching version",
			supportedVersions: []Version{1, 2, 3},
			otherVersions:     []Version{6, 5, 4, 3},
			expectedVersion:   3,
			expectedOK:        true,
		},
		{
			name:              "picks preferred version",
			supportedVersions: []Version{2, 1, 3},
			otherVersions:     []Version{3, 6, 1, 8, 2, 10},
			expectedVersion:   2,
			expectedOK:        true,
		},
		{
			name:              "no matching version",
			supportedVersions: []Version{1},
			otherVersions:     []Version{2},
			expectedOK:        false,
		},
		{
			name:              "empty supported versions",
			supportedVersions: []Version{},
			otherVersions:     []Version{1, 2},
			expectedOK:        false,
		},
		{
			name:              "empty other versions",
			supportedVersions: []Version{102, 101},
			otherVersions:     []Version{},
			expectedOK:        false,
		},
		{
			name:              "both empty",
			supportedVersions: []Version{},
			otherVersions:     []Version{},
			expectedOK:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ver, ok := ChooseSupportedVersion(tt.supportedVersions, tt.otherVersions)
			require.Equal(t, tt.expectedOK, ok)
			if tt.expectedOK {
				require.Equal(t, tt.expectedVersion, ver)
			}
		})
	}
}

func isReservedVersion(v Version) bool { return v&0x0f0f0f0f == 0x0a0a0a0a }

func TestVersionGreasing(t *testing.T) {
	// adding to an empty slice
	greased := GetGreasedVersions([]Version{})
	require.Len(t, greased, 1)
	require.True(t, isReservedVersion(greased[0]))

	// make sure that the greased versions are distinct,
	// allowing for a small number of duplicates
	var versions []Version
	for range 25 {
		versions = GetGreasedVersions(versions)
	}
	slices.Sort(versions)
	var numDuplicates int
	for i, v := range versions {
		require.True(t, isReservedVersion(v))
		if i > 0 && versions[i-1] == v {
			numDuplicates++
		}
	}
	require.LessOrEqual(t, numDuplicates, 3)

	// adding it somewhere in a slice of supported versions
	supported := []Version{10, 18, 29}
	for _, v := range supported {
		require.False(t, isReservedVersion(v))
	}

	var greasedVersionFirst, greasedVersionLast, greasedVersionMiddle int
	for range 100 {
		greased := GetGreasedVersions(supported)
		require.Len(t, greased, 4)

		var j int
		for i, v := range greased {
			if isReservedVersion(v) {
				if i == 0 {
					greasedVersionFirst++
				}
				if i == len(greased)-1 {
					greasedVersionLast++
				}
				greasedVersionMiddle++
				continue
			}
			require.Equal(t, supported[j], v)
			j++
		}
	}
	require.NotZero(t, greasedVersionFirst)
	require.NotZero(t, greasedVersionLast)
	require.NotZero(t, greasedVersionMiddle)
}
