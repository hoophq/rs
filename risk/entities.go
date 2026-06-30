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

// catalog maps a canonical entity type -> severity + data family. The entity
// names are the same canonical set the alcatraz engine emits, so the model
// stays compatible across engines. Unknown types default to low / "Other".
var catalog = map[string]EntityInfo{
	// Secrets — the top exposure for AI coding sessions.
	"API_KEY":        {SeverityHigh, "Secret"},
	"AWS_ACCESS_KEY": {SeverityHigh, "Secret"},
	"PRIVATE_KEY":    {SeverityHigh, "Secret"},
	"PASSWORD":       {SeverityHigh, "Secret"},

	// Financial.
	"CREDIT_CARD":    {SeverityHigh, "Financial"},
	"US_BANK_NUMBER": {SeverityHigh, "Financial"},
	"IBAN_CODE":      {SeverityHigh, "Financial"},
	"CRYPTO":         {SeverityHigh, "Financial"},
	"ABA_ROUTING":    {SeverityMedium, "Financial"},
	// Business / tax registration numbers are typically public.
	"AU_ABN":      {SeverityLow, "Financial"},
	"AU_ACN":      {SeverityLow, "Financial"},
	"IN_GSTIN":    {SeverityLow, "Financial"},
	"IT_VAT_CODE": {SeverityLow, "Financial"},
	"SG_UEN":      {SeverityLow, "Financial"},

	// Government / national identifiers — personal ones are high severity.
	"US_SSN":                    {SeverityHigh, "Government ID"},
	"US_ITIN":                   {SeverityHigh, "Government ID"},
	"UK_NINO":                   {SeverityHigh, "Government ID"},
	"AU_TFN":                    {SeverityHigh, "Government ID"},
	"IN_AADHAAR":                {SeverityHigh, "Government ID"},
	"IN_PAN":                    {SeverityHigh, "Government ID"},
	"IT_FISCAL_CODE":            {SeverityHigh, "Government ID"},
	"ES_NIF":                    {SeverityHigh, "Government ID"},
	"ES_NIE":                    {SeverityHigh, "Government ID"},
	"SG_FIN":                    {SeverityHigh, "Government ID"},
	"PL_PESEL":                  {SeverityHigh, "Government ID"},
	"KR_RRN":                    {SeverityHigh, "Government ID"},
	"FI_PERSONAL_IDENTITY_CODE": {SeverityHigh, "Government ID"},
	"TH_TNIN":                   {SeverityHigh, "Government ID"},
	"US_PASSPORT":               {SeverityMedium, "Government ID"},
	"US_DRIVER_LICENSE":         {SeverityMedium, "Government ID"},
	"IN_PASSPORT":               {SeverityMedium, "Government ID"},
	"IN_VOTER":                  {SeverityMedium, "Government ID"},
	"IT_PASSPORT":               {SeverityMedium, "Government ID"},
	"IT_IDENTITY_CARD":          {SeverityMedium, "Government ID"},
	"IT_DRIVER_LICENSE":         {SeverityMedium, "Government ID"},
	"IN_VEHICLE_REGISTRATION":   {SeverityLow, "Other"},

	// Health.
	"UK_NHS":          {SeverityHigh, "Health"},
	"AU_MEDICARE":     {SeverityHigh, "Health"},
	"MEDICAL_LICENSE": {SeverityMedium, "Health"},
	"MEDICAL_RECORD":  {SeverityMedium, "Health"},

	// Contact / network.
	"EMAIL_ADDRESS": {SeverityMedium, "Contact"},
	"PHONE_NUMBER":  {SeverityMedium, "Contact"},
	"IP_ADDRESS":    {SeverityMedium, "Network"},
	"URL":           {SeverityLow, "Network"},

	// Identity (NER — requires a model; reserved for a future engine).
	"PERSON":   {SeverityLow, "Identity"},
	"LOCATION": {SeverityLow, "Identity"},
	"NRP":      {SeverityLow, "Identity"},

	// Context.
	"DATE_TIME": {SeverityLow, "Context"},
}

// Info returns the severity and family for an entity type.
func Info(entity string) EntityInfo {
	if info, ok := catalog[entity]; ok {
		return info
	}
	return EntityInfo{SeverityLow, "Other"}
}
