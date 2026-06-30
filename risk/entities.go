// Package risk turns raw detections into the risk model rendered by the
// report: per-session tiers, severity-weighted exposure, entity aggregates and
// an overall security score. The severity/family catalog and the scoring rules
// are a faithful port of the dashboard's data adapter so the numbers match.
package risk

// Severity drives the traffic-light risk tiers.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

// severityWeight is the exposure weight per severity (high counts most).
var severityWeight = map[Severity]float64{
	SeverityHigh:   3,
	SeverityMedium: 2,
	SeverityLow:    1,
}

// severityRank orders severities for sorting (high first).
var severityRank = map[Severity]int{
	SeverityHigh:   0,
	SeverityMedium: 1,
	SeverityLow:    2,
}

// EntityInfo is the severity and data family of an entity type.
type EntityInfo struct {
	Severity Severity
	Family   string
}

// catalog maps Presidio entity type -> severity + data family. Unknown types
// default to low severity / "Other".
var catalog = map[string]EntityInfo{
	"US_SSN":            {SeverityHigh, "Government ID"},
	"US_ITIN":           {SeverityHigh, "Government ID"},
	"UK_NINO":           {SeverityHigh, "Government ID"},
	"CREDIT_CARD":       {SeverityHigh, "Financial"},
	"US_BANK_NUMBER":    {SeverityHigh, "Financial"},
	"IBAN_CODE":         {SeverityHigh, "Financial"},
	"CRYPTO":            {SeverityHigh, "Financial"},
	"API_KEY":           {SeverityHigh, "Secret"},
	"AWS_ACCESS_KEY":    {SeverityHigh, "Secret"},
	"PRIVATE_KEY":       {SeverityHigh, "Secret"},
	"PASSWORD":          {SeverityHigh, "Secret"},
	"US_PASSPORT":       {SeverityMedium, "Government ID"},
	"US_DRIVER_LICENSE": {SeverityMedium, "Government ID"},
	"MEDICAL_LICENSE":   {SeverityMedium, "Health"},
	"MEDICAL_RECORD":    {SeverityMedium, "Health"},
	"EMAIL_ADDRESS":     {SeverityMedium, "Contact"},
	"PHONE_NUMBER":      {SeverityMedium, "Contact"},
	"IP_ADDRESS":        {SeverityMedium, "Network"},
	"PERSON":            {SeverityLow, "Identity"},
	"LOCATION":          {SeverityLow, "Identity"},
	"NRP":               {SeverityLow, "Identity"},
	"URL":               {SeverityLow, "Network"},
	"DATE_TIME":         {SeverityLow, "Context"},
}

// Info returns the severity and family for an entity type.
func Info(entity string) EntityInfo {
	if info, ok := catalog[entity]; ok {
		return info
	}
	return EntityInfo{SeverityLow, "Other"}
}
