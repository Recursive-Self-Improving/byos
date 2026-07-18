// Billing schema parsing is derived in part from kenryu42/pi-grok-cli,
// src/provider/billing.ts, licensed under the MIT License.

package usage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"byos/internal/xai"
)

var ErrSchema = errors.New("invalid xai billing schema")

type BillingResult struct {
	Monthly *Monthly
	Weekly  *Weekly
	Raw     json.RawMessage
}

type BillingAdapter struct{ client *xai.Client }

func NewBillingAdapter(client *xai.Client) *BillingAdapter { return &BillingAdapter{client: client} }

func (a *BillingAdapter) Fetch(ctx context.Context, token string) (BillingResult, error) {
	result := BillingResult{}
	rawParts := make(map[string]json.RawMessage, 2)
	monthlyRaw, monthlyErr := a.get(ctx, token, "billing")
	if monthlyErr == nil {
		monthly, parseErr := parseMonthly(monthlyRaw)
		monthlyErr = parseErr
		if parseErr == nil {
			result.Monthly = &monthly
			rawParts["monthly"] = monthlyRaw
		}
	}
	weeklyRaw, weeklyErr := a.get(ctx, token, "billing?format=credits")
	if weeklyErr == nil {
		weekly, parseErr := parseWeekly(weeklyRaw)
		weeklyErr = parseErr
		if parseErr == nil && weekly != nil {
			result.Weekly = weekly
			rawParts["credits"] = weeklyRaw
		}
	}
	if result.Monthly == nil && result.Weekly == nil {
		return BillingResult{}, errors.Join(monthlyErr, weeklyErr, ErrSchema)
	}
	raw, err := json.Marshal(rawParts)
	if err != nil {
		return BillingResult{}, err
	}
	result.Raw = raw
	return result, nil
}

func (a *BillingAdapter) get(ctx context.Context, token, endpoint string) (json.RawMessage, error) {
	response, err := a.client.Do(ctx, http.MethodGet, endpoint, token, "", "application/json", nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &HTTPError{Status: response.StatusCode, RetryAfter: response.Header.Get("Retry-After")}
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if !json.Valid(payload) {
		return nil, ErrSchema
	}
	return payload, nil
}

func parseMonthly(payload []byte) (Monthly, error) {
	config, err := billingConfig(payload)
	if err != nil {
		return Monthly{}, err
	}
	limit, err := requiredVal(config, "monthlyLimit")
	if err != nil {
		return Monthly{}, err
	}
	used, err := requiredVal(config, "used")
	if err != nil {
		return Monthly{}, err
	}
	reset, err := requiredTime(config, "billingPeriodEnd")
	if err != nil {
		return Monthly{}, err
	}
	return Monthly{Limit: limit, Used: used, Remaining: limit - used, ResetAt: reset}, nil
}

func parseWeekly(payload []byte) (*Weekly, error) {
	config, err := billingConfig(payload)
	if err != nil {
		return nil, err
	}
	periodRaw, ok := config["currentPeriod"]
	if !ok {
		return nil, ErrSchema
	}
	var period map[string]json.RawMessage
	if json.Unmarshal(periodRaw, &period) != nil {
		return nil, ErrSchema
	}
	var periodType string
	if value, ok := period["type"]; !ok || json.Unmarshal(value, &periodType) != nil {
		return nil, ErrSchema
	}
	if periodType != "USAGE_PERIOD_TYPE_WEEKLY" {
		return nil, nil
	}
	used, err := requiredNumber(config, "creditUsagePercent")
	if err != nil || used < 0 || used > 100 {
		return nil, ErrSchema
	}
	reset, err := requiredTime(config, "billingPeriodEnd")
	if err != nil {
		return nil, err
	}
	onDemand, err := optionalCredit(config, "onDemand", "onDemandCredits")
	if err != nil {
		return nil, err
	}
	prepaid, err := optionalCredit(config, "prepaid", "prepaidCredits")
	if err != nil {
		return nil, err
	}
	return &Weekly{UsedPercent: used, RemainingPercent: 100 - used, ResetAt: reset, OnDemand: onDemand, Prepaid: prepaid}, nil
}

func billingConfig(payload []byte) (map[string]json.RawMessage, error) {
	var root map[string]json.RawMessage
	if json.Unmarshal(payload, &root) != nil {
		return nil, ErrSchema
	}
	raw, ok := root["config"]
	if !ok {
		return nil, ErrSchema
	}
	var config map[string]json.RawMessage
	if json.Unmarshal(raw, &config) != nil {
		return nil, ErrSchema
	}
	return config, nil
}

func requiredVal(config map[string]json.RawMessage, key string) (float64, error) {
	raw, ok := config[key]
	if !ok {
		return 0, ErrSchema
	}
	var wrapped map[string]json.RawMessage
	if json.Unmarshal(raw, &wrapped) != nil {
		return 0, ErrSchema
	}
	return requiredNumber(wrapped, "val")
}
func requiredNumber(fields map[string]json.RawMessage, key string) (float64, error) {
	raw, ok := fields[key]
	if !ok {
		return 0, ErrSchema
	}
	var value float64
	if json.Unmarshal(raw, &value) != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0, ErrSchema
	}
	return value, nil
}
func requiredTime(fields map[string]json.RawMessage, key string) (time.Time, error) {
	raw, ok := fields[key]
	if !ok {
		return time.Time{}, ErrSchema
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return time.Time{}, ErrSchema
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: invalid reset time", ErrSchema)
	}
	return parsed, nil
}
func optionalCredit(fields map[string]json.RawMessage, keys ...string) (*float64, error) {
	for _, key := range keys {
		raw, ok := fields[key]
		if !ok || string(raw) == "null" {
			continue
		}
		var direct float64
		if json.Unmarshal(raw, &direct) == nil {
			if math.IsNaN(direct) || math.IsInf(direct, 0) || direct < 0 {
				return nil, ErrSchema
			}
			return &direct, nil
		}
		var wrapped map[string]json.RawMessage
		if json.Unmarshal(raw, &wrapped) != nil {
			return nil, ErrSchema
		}
		value, err := requiredNumber(wrapped, "val")
		if err != nil {
			return nil, err
		}
		return &value, nil
	}
	return nil, nil
}
