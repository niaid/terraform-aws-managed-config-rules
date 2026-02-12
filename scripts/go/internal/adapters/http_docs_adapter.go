package adapters

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"scripts/go/internal/domain"

	"github.com/PuerkitoBio/goquery"
)

const defaultConcurrency = 10

// HttpConfigRuleDataSource scrapes AWS documentation for Config Rule data.
type HttpConfigRuleDataSource struct {
	RootURL          string
	ManagedRulesPage string
}

func (s *HttpConfigRuleDataSource) Load() ([]domain.RawConfigRuleData, error) {
	doc, err := fetchDocument(s.ManagedRulesPage)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch managed rules page: %w", err)
	}

	ruleNames := getConfigRulesList(doc)
	result := make([]domain.RawConfigRuleData, len(ruleNames))
	errors := make([]error, len(ruleNames))

	sem := make(chan struct{}, defaultConcurrency)
	var wg sync.WaitGroup

	for i, ruleName := range ruleNames {
		wg.Add(1)
		go func(idx int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			log.Printf("Parsing %s", name)
			ruleDoc, err := fetchDocument(s.RootURL + name)
			if err != nil {
				log.Printf("Error fetching rule %s: %v", name, err)
				errors[idx] = err
				return
			}
			mainCol := ruleDoc.Find("div#main-col-body")
			result[idx] = domain.RawConfigRuleData{
				Name:          name,
				Identifier:    getRuleIdentifier(mainCol),
				Description:   getRuleDescription(mainCol),
				Parameters:    getRuleParameters(mainCol),
				ResourceTypes: getResourceTypes(mainCol),
			}
		}(i, ruleName)
	}

	wg.Wait()

	// Filter out failed fetches (zero-value entries).
	var filtered []domain.RawConfigRuleData
	for i, r := range result {
		if errors[i] == nil {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}

// HttpSecurityHubDataSource scrapes AWS documentation for Security Hub control data.
type HttpSecurityHubDataSource struct {
	RootURL         string
	ControlsRefPage string
}

func (s *HttpSecurityHubDataSource) Load() ([]domain.RawSecurityHubControlData, error) {
	refURL := s.RootURL + "/" + s.ControlsRefPage
	doc, err := fetchDocument(refURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch controls reference page: %w", err)
	}

	controlPages := getSecurityHubControlPages(doc)
	pageResults := make([][]domain.RawSecurityHubControlData, len(controlPages))

	sem := make(chan struct{}, defaultConcurrency)
	var wg sync.WaitGroup

	for i, page := range controlPages {
		wg.Add(1)
		go func(idx int, pg string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			pageURL := s.RootURL + strings.TrimPrefix(pg, ".")
			pageDoc, err := fetchDocument(pageURL)
			if err != nil {
				log.Printf("Error fetching control page %s: %v", pg, err)
				return
			}
			pageResults[idx] = parseSecurityHubControlPage(pageDoc)
		}(i, page)
	}

	wg.Wait()

	var result []domain.RawSecurityHubControlData
	for _, controls := range pageResults {
		result = append(result, controls...)
	}
	return result, nil
}

// --- Helper functions (all HTML parsing logic lives here) ---

func fetchDocument(url string) (*goquery.Document, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return goquery.NewDocumentFromReader(resp.Body)
}

func getConfigRulesList(doc *goquery.Document) []string {
	var rules []string
	doc.Find("h6").Each(func(_ int, s *goquery.Selection) {
		if strings.TrimSpace(s.Text()) == "Topics" {
			s.NextAll().First().Find("li").Each(func(_ int, li *goquery.Selection) {
				rules = append(rules, strings.TrimSpace(li.Text()))
			})
		}
	})
	return rules
}

func getRuleIdentifier(mainCol *goquery.Selection) string {
	var identifier string
	mainCol.Find("b").Each(func(_ int, b *goquery.Selection) {
		if strings.TrimSpace(b.Text()) == "Identifier:" {
			next := b.Nodes[0].NextSibling
			if next != nil {
				identifier = strings.TrimSpace(next.Data)
			}
		}
	})
	return identifier
}

func getRuleDescription(mainCol *goquery.Selection) string {
	var description string
	mainCol.Children().Each(func(_ int, child *goquery.Selection) {
		if description != "" {
			return
		}
		if goquery.NodeName(child) == "p" {
			description = strings.TrimSpace(child.Text())
		}
	})
	return cleanStringWithTags(description)
}

func cleanStringWithTags(value string) string {
	value = strings.ReplaceAll(value, "''", "`")
	value = strings.Trim(value, "'")
	return value
}

func getRuleParameters(mainCol *goquery.Selection) []domain.ParameterData {
	varList := mainCol.Find("div.variablelist")
	if varList.Length() == 0 {
		return []domain.ParameterData{}
	}

	var params []domain.ParameterData
	var current domain.ParameterData
	hasName := false

	varList.Find("dl").Children().Each(func(_ int, child *goquery.Selection) {
		text := strings.TrimSpace(child.Text())
		if text == "None" || text == "\n" || text == "" {
			return
		}
		tag := goquery.NodeName(child)

		if tag == "dt" && strings.Contains(text, "Type:") {
			parts := strings.Split(text, " ")
			current.Type = parts[len(parts)-1]
		} else if tag == "dt" && strings.Contains(text, "Default:") {
			defVal := strings.Split(text, "Default:")
			if len(defVal) > 1 {
				current.Default = strings.TrimSpace(strings.ReplaceAll(defVal[1], "(Optional)", ""))
			}
		} else if tag == "dt" && !hasName {
			parts := strings.Split(text, " ")
			current.Name = parts[0]
			current.Optional = strings.HasSuffix(strings.TrimSpace(text), "(Optional)")
			hasName = true
		} else if tag == "dd" {
			p := child.Find("p")
			if p.Length() > 0 {
				current.Description = strings.TrimSpace(p.Text())
			}
			params = append(params, current)
			current = domain.ParameterData{}
			hasName = false
		}
	})
	return params
}

func getResourceTypes(mainCol *goquery.Selection) []string {
	var types []string
	mainCol.Find("b").Each(func(_ int, b *goquery.Selection) {
		if strings.TrimSpace(b.Text()) == "Resource Types:" {
			next := b.Nodes[0].NextSibling
			if next != nil {
				for _, t := range strings.Split(next.Data, ",") {
					trimmed := strings.TrimSpace(t)
					if trimmed != "" {
						types = append(types, trimmed)
					}
				}
			}
		}
	})
	return types
}

var awsConfigRulePattern = regexp.MustCompile(`(?i)aws\s?config\s?rule`)

func getSecurityHubControlPages(doc *goquery.Document) []string {
	seen := make(map[string]bool)
	var pages []string

	// The controls reference page uses a table with links like
	// "./account-controls.html#account-1". We extract unique page paths
	// (without the fragment) from the table rows.
	doc.Find("table a").Each(func(_ int, a *goquery.Selection) {
		href, exists := a.Attr("href")
		if !exists {
			return
		}
		// Strip fragment (e.g. "#account-1")
		if idx := strings.Index(href, "#"); idx != -1 {
			href = href[:idx]
		}
		href = strings.TrimPrefix(href, ".")
		if href == "" || seen[href] {
			return
		}
		// Only include control page links (contain "-controls")
		if !strings.Contains(href, "-controls") {
			return
		}
		seen[href] = true
		pages = append(pages, href)
	})

	// Fallback: try the legacy Topics/list format
	if len(pages) == 0 {
		doc.Find("h6").Each(func(_ int, s *goquery.Selection) {
			if strings.TrimSpace(s.Text()) == "Topics" {
				s.NextAll().First().Find("li").Each(func(_ int, li *goquery.Selection) {
					href, exists := li.Find("a").First().Attr("href")
					if exists {
						pages = append(pages, strings.TrimSuffix(href, "."))
					}
				})
			}
		})
	}
	return pages
}

func parseSecurityHubControlPage(doc *goquery.Document) []domain.RawSecurityHubControlData {
	var result []domain.RawSecurityHubControlData
	doc.Find("h2").Each(func(_ int, h2 *goquery.Selection) {
		controlName := strings.TrimSpace(h2.Text())
		var severity, rule string

		h2.NextAll().Each(func(_ int, sib *goquery.Selection) {
			if severity != "" && rule != "" {
				return
			}
			if goquery.NodeName(sib) == "h2" {
				return // stop at next control
			}
			if goquery.NodeName(sib) != "p" {
				return
			}
			sib.Find("b").Each(func(_ int, b *goquery.Selection) {
				bText := strings.TrimSpace(b.Text())
				if strings.Contains(bText, "Severity") && severity == "" {
					next := b.Nodes[0].NextSibling
					if next != nil {
						severity = strings.TrimSpace(next.Data)
					}
				}
				if awsConfigRulePattern.MatchString(bText) && rule == "" {
					// Look for <a> or <code> sibling
					b.Parent().Find("a").Each(func(_ int, a *goquery.Selection) {
						if rule == "" {
							rule = strings.TrimSpace(a.Text())
						}
					})
					if rule == "" {
						b.Parent().Find("code").Each(func(_ int, code *goquery.Selection) {
							if rule == "" {
								rule = strings.TrimSpace(code.Text())
							}
						})
					}
				}
			})
			// Check for "None" text indicating no config rule
			if rule == "" {
				text := strings.TrimSpace(sib.Text())
				if strings.HasPrefix(text, "None") {
					rule = "NO_CONFIG_RULE_CONFIGURED"
				}
			}
		})

		if severity != "" && rule != "" && rule != "NO_CONFIG_RULE_CONFIGURED" {
			result = append(result, domain.RawSecurityHubControlData{
				Severity: severity,
				Rule:     rule,
				Control:  controlName,
			})
		}
	})
	return result
}
