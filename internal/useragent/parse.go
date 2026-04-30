// Package useragent parses User-Agent strings into human-readable device descriptions.
package useragent

import "strings"

// FriendlyName generates a human-readable device name from a User-Agent string.
// Examples: "Chrome on Windows", "Safari on iPhone", "Firefox on Linux".
func FriendlyName(ua string) string {
	if ua == "" {
		return "Unknown Device"
	}

	browser := parseBrowser(ua)
	os := parseOS(ua)

	if browser == "" && os == "" {
		return "Unknown Device"
	}
	if browser == "" {
		return os
	}
	if os == "" {
		return browser
	}
	return browser + " on " + os
}

func parseBrowser(ua string) string {
	// Order matters — check specific browsers before generic ones.
	// Edge contains "Chrome", Chrome contains "Safari", etc.
	switch {
	case contains(ua, "Edg/") || contains(ua, "Edge/"):
		return "Edge"
	case contains(ua, "OPR/") || contains(ua, "Opera"):
		return "Opera"
	case contains(ua, "Vivaldi/"):
		return "Vivaldi"
	case contains(ua, "Brave"):
		return "Brave"
	case contains(ua, "SamsungBrowser/"):
		return "Samsung Internet"
	case contains(ua, "YaBrowser/"):
		return "Yandex"
	case contains(ua, "Firefox/") || contains(ua, "FxiOS/"):
		return "Firefox"
	case contains(ua, "CriOS/"):
		return "Chrome"
	case contains(ua, "Chrome/") && !contains(ua, "Chromium/"):
		return "Chrome"
	case contains(ua, "Chromium/"):
		return "Chromium"
	case contains(ua, "Safari/") && contains(ua, "Version/"):
		return "Safari"
	case contains(ua, "MSIE") || contains(ua, "Trident/"):
		return "Internet Explorer"
	case contains(ua, "curl/"):
		return "curl"
	case contains(ua, "Wget/"):
		return "Wget"
	case contains(ua, "PostmanRuntime/"):
		return "Postman"
	case contains(ua, "insomnia/"):
		return "Insomnia"
	default:
		return ""
	}
}

func parseOS(ua string) string {
	switch {
	case contains(ua, "iPhone"):
		return "iPhone"
	case contains(ua, "iPad"):
		return "iPad"
	case contains(ua, "Android"):
		return "Android"
	case contains(ua, "CrOS"):
		return "ChromeOS"
	case contains(ua, "Windows"):
		return "Windows"
	case contains(ua, "Macintosh") || contains(ua, "Mac OS"):
		return "macOS"
	case contains(ua, "Linux"):
		return "Linux"
	case contains(ua, "FreeBSD"):
		return "FreeBSD"
	case contains(ua, "OpenBSD"):
		return "OpenBSD"
	default:
		return ""
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
