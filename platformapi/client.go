package platformapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	containerEventType    = "containerEvent"
	hostAPIProxyTokenType = "hostApiProxyToken"
	defaultTimeout        = 30 * time.Second
	maxResponseBytes      = 4 << 20
	maxRequestBytes       = 4 << 20
	maxErrorBytes         = 64 << 10
)

type ClientOpts struct {
	URL        string
	AccessKey  string
	SecretKey  string
	HTTPClient *http.Client
}

type Client struct {
	ContainerEvent    ContainerEventCreator
	HostAPIProxyToken HostAPIProxyTokenCreator
}

type ContainerEventCreator interface {
	Create(*ContainerEvent) (*ContainerEvent, error)
}

type HostAPIProxyTokenCreator interface {
	Create(*HostAPIProxyToken) (*HostAPIProxyToken, error)
}

type ContainerEvent struct {
	DockerInspect     interface{} `json:"dockerInspect,omitempty"`
	ExternalFrom      string      `json:"externalFrom,omitempty"`
	ExternalID        string      `json:"externalId,omitempty"`
	ExternalStatus    string      `json:"externalStatus,omitempty"`
	ExternalTimestamp int64       `json:"externalTimestamp,omitempty"`
	ReportedHostUUID  string      `json:"reportedHostUuid,omitempty"`
}

type HostAPIProxyToken struct {
	ReportedUUID string `json:"reportedUuid,omitempty"`
	Token        string `json:"token,omitempty"`
	URL          string `json:"url,omitempty"`
}

type APIError struct {
	StatusCode int
	URL        string
	Status     string
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("control-platform request to %s returned %s", safeURLForError(e.URL), e.Status)
}

type schemaCollection struct {
	Data []schema `json:"data"`
}

type schema struct {
	ID                string            `json:"id"`
	PluralName        string            `json:"pluralName"`
	Links             map[string]string `json:"links"`
	CollectionMethods []string          `json:"collectionMethods"`
}

type client struct {
	httpClient *http.Client
	accessKey  string
	secretKey  string
	origin     string
	collection string
}

func NewClient(opts ClientOpts) (*Client, error) {
	baseURL, err := validateURL(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid control-platform URL: %w", err)
	}

	httpClient := cloneHTTPClient(opts.HTTPClient)
	httpClient.CheckRedirect = sameOriginRedirectPolicy(httpClient.CheckRedirect)
	origin := urlOrigin(baseURL)

	requestClient := &client{
		httpClient: httpClient,
		accessKey:  opts.AccessKey,
		secretKey:  opts.SecretKey,
		origin:     origin,
	}

	schemas, err := requestClient.loadSchemas(baseURL)
	if err != nil {
		return nil, err
	}

	collections := make(map[string]string, 2)
	for _, typeName := range []string{containerEventType, hostAPIProxyTokenType} {
		collectionURL, err := collectionURL(schemas, typeName, baseURL, origin)
		if err != nil {
			return nil, err
		}
		collections[typeName] = collectionURL
	}

	return &Client{
		ContainerEvent:    &containerEventClient{client: requestClient.withCollection(collections[containerEventType])},
		HostAPIProxyToken: &hostAPIProxyTokenClient{client: requestClient.withCollection(collections[hostAPIProxyTokenType])},
	}, nil
}

func cloneHTTPClient(source *http.Client) *http.Client {
	if source == nil {
		return &http.Client{Timeout: defaultTimeout}
	}
	clone := *source
	if clone.Timeout <= 0 {
		clone.Timeout = defaultTimeout
	}
	return &clone
}

func sameOriginRedirectPolicy(existing func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if len(via) > 0 && urlOrigin(req.URL) != urlOrigin(via[0].URL) {
			return errors.New("refusing cross-origin redirect")
		}
		if existing != nil {
			return existing(req, via)
		}
		return nil
	}
}

func validateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("URL scheme must be http or https")
	}
	if u.Host == "" {
		return nil, errors.New("URL host is required")
	}
	if u.User != nil {
		return nil, errors.New("URL user information is not allowed")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("URL query and fragment are not allowed")
	}
	return u, nil
}

func safeURLForError(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid URL>"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func urlOrigin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else if strings.EqualFold(u.Scheme, "http") {
			port = "80"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

func (c *client) loadSchemas(baseURL *url.URL) ([]schema, error) {
	resp, err := c.do(http.MethodGet, baseURL.String(), nil)
	if err != nil {
		return nil, err
	}

	schemaHeader := strings.TrimSpace(resp.Header.Get("X-API-Schemas"))
	if schemaHeader == "" {
		resp.Body.Close()
		return nil, errors.New("control-platform response did not provide X-API-Schemas")
	}

	schemaURL, err := baseURL.Parse(schemaHeader)
	if err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("invalid schema URL: %w", err)
	}
	if urlOrigin(schemaURL) != c.origin {
		resp.Body.Close()
		return nil, errors.New("refusing cross-origin schema URL")
	}
	if schemaURL.User != nil || schemaURL.RawQuery != "" || schemaURL.Fragment != "" {
		resp.Body.Close()
		return nil, errors.New("schema URL must not contain user information, a query, or a fragment")
	}

	if schemaURL.String() != baseURL.String() {
		resp.Body.Close()
		resp, err = c.do(http.MethodGet, schemaURL.String(), nil)
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	var collection schemaCollection
	if err := decodeBoundedJSON(resp.Body, maxResponseBytes, &collection); err != nil {
		return nil, fmt.Errorf("decode control-platform schemas: %w", err)
	}
	return collection.Data, nil
}

func collectionURL(schemas []schema, typeName string, baseURL *url.URL, origin string) (string, error) {
	for _, item := range schemas {
		if item.ID != typeName {
			continue
		}
		if !containsFold(item.CollectionMethods, http.MethodPost) {
			return "", fmt.Errorf("control-platform resource %s is not creatable", typeName)
		}

		raw := strings.TrimSpace(item.Links["collection"])
		if raw == "" {
			self := strings.TrimSpace(item.Links["self"])
			if self == "" || item.PluralName == "" {
				return "", fmt.Errorf("control-platform resource %s has no collection URL", typeName)
			}
			selfURL, err := baseURL.Parse(self)
			if err != nil {
				return "", fmt.Errorf("invalid %s schema URL: %w", typeName, err)
			}
			marker := "/schemas/"
			index := strings.LastIndex(selfURL.Path, marker)
			if index < 0 {
				return "", fmt.Errorf("cannot derive %s collection URL", typeName)
			}
			selfURL.Path = selfURL.Path[:index] + "/" + item.PluralName
			selfURL.RawPath = ""
			selfURL.RawQuery = ""
			raw = selfURL.String()
		}

		collection, err := baseURL.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("invalid %s collection URL: %w", typeName, err)
		}
		if urlOrigin(collection) != origin {
			return "", fmt.Errorf("refusing cross-origin %s collection URL", typeName)
		}
		if collection.User != nil || collection.RawQuery != "" || collection.Fragment != "" {
			return "", fmt.Errorf("%s collection URL contains user information, a query, or a fragment", typeName)
		}
		return collection.String(), nil
	}
	return "", fmt.Errorf("control-platform schema %s is unavailable", typeName)
}

func containsFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

func (c *client) withCollection(collection string) *client {
	clone := *c
	clone.collection = collection
	return &clone
}

func (c *client) do(method, target string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.accessKey, c.secretKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		defer resp.Body.Close()
		contents, readErr := readBounded(resp.Body, maxErrorBytes)
		if readErr != nil {
			return nil, readErr
		}
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			URL:        target,
			Status:     resp.Status,
			Body:       string(contents),
		}
	}
	return resp, nil
}

func (c *client) create(request, response interface{}) error {
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if len(encoded) > maxRequestBytes {
		return fmt.Errorf("request body exceeds %d bytes", maxRequestBytes)
	}
	resp, err := c.do(http.MethodPost, c.collection, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeBoundedJSON(resp.Body, maxResponseBytes, response)
}

func decodeBoundedJSON(reader io.Reader, maximum int64, target interface{}) error {
	contents, err := readBounded(reader, maximum)
	if err != nil {
		return err
	}
	if len(contents) == 0 {
		return nil
	}
	if err := json.Unmarshal(contents, target); err != nil {
		return err
	}
	return nil
}

func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	contents, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > maximum {
		return nil, fmt.Errorf("response body exceeds %d bytes", maximum)
	}
	return contents, nil
}

type containerEventClient struct {
	client *client
}

func (c *containerEventClient) Create(request *ContainerEvent) (*ContainerEvent, error) {
	response := &ContainerEvent{}
	if err := c.client.create(request, response); err != nil {
		return nil, err
	}
	return response, nil
}

type hostAPIProxyTokenClient struct {
	client *client
}

func (c *hostAPIProxyTokenClient) Create(request *HostAPIProxyToken) (*HostAPIProxyToken, error) {
	response := &HostAPIProxyToken{}
	if err := c.client.create(request, response); err != nil {
		return nil, err
	}
	return response, nil
}
