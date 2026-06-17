package updater

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AtomFeed represents a parsed Atom feed
type AtomFeed struct {
	XMLName xml.Name    `xml:"feed"`
	Title   string      `xml:"title"`
	Entries []AtomEntry `xml:"entry"`
}

// AtomEntry represents a single entry (release) in the feed
type AtomEntry struct {
	ID      string    `xml:"id"`
	Title   string    `xml:"title"`
	Updated time.Time `xml:"updated"`
	Link    AtomLink  `xml:"link"`
	Content string    `xml:"content"`
}

// AtomLink represents a link element
type AtomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
	Type string `xml:"type,attr"`
}

// Release represents a parsed release from the feed
type Release struct {
	Version string
	Tag     string
	Date    time.Time
	URL     string
}

// FeedParser handles fetching and parsing Atom feeds
type FeedParser struct {
	feedURL string
	client  *http.Client
}

// NewFeedParser creates a new feed parser
func NewFeedParser(feedURL string) *FeedParser {
	return &FeedParser{
		feedURL: feedURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// extractTagFromID extracts the tag name from an atom entry ID.
// The ID format is: tag:github.com,2008:Repository/{repo_id}/{tag}
// For example: tag:github.com,2008:Repository/1114756634/v0.1.72 -> v0.1.72
//
// We use the ID instead of the Title because GitHub may temporarily show
// a corrupted title during release creation (e.g., "v0.1.72: ## 🎯 Highlights")
// while the ID always contains the correct tag name.
func extractTagFromID(id string) string {
	lastSlash := strings.LastIndex(id, "/")
	if lastSlash == -1 || lastSlash == len(id)-1 {
		return ""
	}
	return id[lastSlash+1:]
}

// isReleaseReady checks if an atom entry represents a complete release
// (not just a tag). GitHub shows tags in the atom feed before releases are created.
// When the release exists, the <title> matches the tag name from <id>.
// When only the tag exists, the <title> contains extra content from the tag annotation.
func isReleaseReady(entry AtomEntry) bool {
	tag := extractTagFromID(entry.ID)
	if tag == "" {
		return false
	}
	// If title matches the tag exactly, the release is ready
	return entry.Title == tag
}

// GetLatestRelease fetches and parses the feed to get the latest release
func (fp *FeedParser) GetLatestRelease(ctx context.Context) (*Release, error) {
	// Fetch feed
	req, err := http.NewRequestWithContext(ctx, "GET", fp.feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := fp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch feed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed request failed with status %d", resp.StatusCode)
	}

	// Parse feed
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read feed: %w", err)
	}

	var feed AtomFeed
	if err := xml.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("failed to parse feed XML: %w", err)
	}

	// Find first entry that is a complete release (not just a tag)
	// Tags appear in the feed before releases are created, with corrupted titles
	var entry *AtomEntry
	for i := range feed.Entries {
		if isReleaseReady(feed.Entries[i]) {
			entry = &feed.Entries[i]
			break
		}
	}

	if entry == nil {
		return nil, fmt.Errorf("no releases found in feed (only tags)")
	}

	// Extract tag from ID (more reliable than Title during release creation)
	tag := extractTagFromID(entry.ID)
	if tag == "" {
		return nil, fmt.Errorf("failed to extract tag from entry ID: %s", entry.ID)
	}

	// Strip 'v' prefix if present
	version := tag
	if len(version) > 0 && version[0] == 'v' {
		version = version[1:]
	}

	return &Release{
		Version: version,
		Tag:     tag,
		Date:    entry.Updated,
		URL:     entry.Link.Href,
	}, nil
}

// ListReleases fetches and parses the feed to get all releases
func (fp *FeedParser) ListReleases(ctx context.Context) ([]*Release, error) {
	// Fetch feed
	req, err := http.NewRequestWithContext(ctx, "GET", fp.feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := fp.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch feed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed request failed with status %d", resp.StatusCode)
	}

	// Parse feed
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read feed: %w", err)
	}

	var feed AtomFeed
	if err := xml.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("failed to parse feed XML: %w", err)
	}

	// Convert entries to releases, filtering out tag-only entries
	releases := make([]*Release, 0, len(feed.Entries))
	for _, entry := range feed.Entries {
		// Skip entries that are just tags (not complete releases)
		if !isReleaseReady(entry) {
			continue
		}

		// Extract tag from ID (more reliable than Title during release creation)
		tag := extractTagFromID(entry.ID)
		if tag == "" {
			// Skip entries with unparseable IDs
			continue
		}

		version := tag
		if len(version) > 0 && version[0] == 'v' {
			version = version[1:]
		}

		releases = append(releases, &Release{
			Version: version,
			Tag:     tag,
			Date:    entry.Updated,
			URL:     entry.Link.Href,
		})
	}

	return releases, nil
}
