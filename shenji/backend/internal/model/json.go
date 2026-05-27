package model

import (
	"encoding/json"

	"gorm.io/datatypes"
)

func JSONValue(value any) datatypes.JSON {
	raw, err := json.Marshal(value)
	if err != nil {
		return datatypes.JSON([]byte("{}"))
	}
	return datatypes.JSON(raw)
}

func JSONArray(values ...any) datatypes.JSON {
	raw, err := json.Marshal(values)
	if err != nil {
		return datatypes.JSON([]byte("[]"))
	}
	return datatypes.JSON(raw)
}
