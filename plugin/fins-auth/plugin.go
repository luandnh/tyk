package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/joho/godotenv"
	"github.com/luandnh/fins-tyk-auth-plugin/pb"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

const ERR_TOKEN_IS_EMPTY = "token is empty"
const ERR_TOKEN_IS_INVALID = "token is invalid"
const ERR_TOKEN_IS_EXPIRED = "token is expired"
const ERR_INTERNAL_SERVER_ERROR = "internal server error"

var MAP_ERROR = map[string]string{
	ERR_TOKEN_IS_EMPTY:        "ERR_TOKEN_IS_EMPTY",
	ERR_TOKEN_IS_INVALID:      "ERR_TOKEN_IS_INVALID",
	ERR_TOKEN_IS_EXPIRED:      "ERR_TOKEN_IS_EXPIRED",
	ERR_INTERNAL_SERVER_ERROR: "ERR_INTERNAL_SERVER_ERROR",
}

var skipRoutes = []string{
	// "/health",
	// "/aaa/v1/login",
	// "/aaa/v1/token/refresh",
	// "/aaa/v1/ui-config",
	// "/aaa/v1/password/forgot",
	// "/bss/v1/webhook",
	// "/bss-message/v1/wss",
}

var FinSHeaders = []string{
	"X-Database-User",
	"X-Database-Password",
	"X-Database-Host",
	"X-Database-Port",
	"X-Database-Name",
	"X-User-Id",
	"X-Username",
	"X-Tenant-Id",
	"X-Business-Unit-Id",
	"X-Group-Id",
	"X-Token",
}

type GRPCClient struct {
	Client pb.TokenServiceClient
}

var GRPC_CLI *GRPCClient

// util

func getStringENV(envVar string, defaultValue string) (value string) {
	value = os.Getenv(envVar)
	if len(value) < 1 {
		value = defaultValue
	}
	return
}

func getStringSliceENV(envVar string, defaultValue []string) (value []string) {
	value = defaultValue
	if valueStr := os.Getenv(envVar); len(valueStr) > 0 {
		value = strings.Split(valueStr, ",")
	}
	return
}

func inArray(item any, array any) bool {
	arr := reflect.ValueOf(array)
	if arr.Kind() != reflect.Slice {
		return false
	}
	for i := 0; i < arr.Len(); i++ {
		if arr.Index(i).Interface() == item {
			return true
		}
	}
	return false
}

func inArrayContains(item string, array []string) bool {
	for _, v := range array {
		if strings.Contains(item, v) {
			return true
		}
	}
	return false
}

func responseJson(w http.ResponseWriter, httpStatusInt int, code, message string) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(httpStatusInt)
	errCode, ok := MAP_ERROR[code]
	if !ok {
		errCode = "ERR_INTERNAL_SERVER_ERROR"
	}
	res := map[string]any{
		"code":    errCode,
		"message": message,
	}
	jsonResult, _ := json.Marshal(res)
	_, _ = w.Write(jsonResult)
}

func init() {
	if err := godotenv.Load(); err != nil {
		panic(err)
	}
	aaaHost := getStringENV("AAA_HOST", "aaa-service:8000")
	log.Infof("connecting to %s", aaaHost)
	conn, err := grpc.Dial(aaaHost, grpc.WithInsecure())
	if err != nil {
		log.Errorf("failed to connect to %s: %v", aaaHost, err)
	}
	GRPC_CLI = &GRPCClient{
		Client: pb.NewTokenServiceClient(conn),
	}
	skipRoutes = getStringSliceENV("SKIP_ROUTES", []string{})
	log.Infof("skip routes: %v", skipRoutes)
}

func getToken(header string) string {
	return strings.Replace(header, "Bearer ", "", 1)
}

func FinsAuthMiddleware(resw http.ResponseWriter, req *http.Request) {
	if inArrayContains(req.URL.Path, skipRoutes) {
		return
	}
	token := getToken(req.Header.Get("Authorization"))
	if len(token) < 1 {
		responseJson(resw, http.StatusUnauthorized, "ERR_TOKEN_IS_EMPTY", "unauthorized")
		return
	}
	res, err := GRPC_CLI.Client.VerifyToken(req.Context(), &pb.VerifyTokenRequest{Token: token})
	if err != nil {
		log.Error(err)
		if e, ok := status.FromError(err); ok {
			if inArray(e.Message(), []string{ERR_TOKEN_IS_EMPTY, ERR_TOKEN_IS_INVALID, ERR_TOKEN_IS_EXPIRED}) {
				code := ERR_TOKEN_IS_INVALID
				if err.Error() == ERR_TOKEN_IS_EXPIRED {
					code = ERR_TOKEN_IS_INVALID
				}
				responseJson(resw, http.StatusUnauthorized, code, e.Message())
				return
			}
		}
		responseJson(resw, http.StatusInternalServerError, ERR_INTERNAL_SERVER_ERROR, err.Error())
		return
	}
	data := res.GetData()
	req.Header.Set("X-Database-User", data.GetDatabaseUser())
	req.Header.Set("X-Database-Password", data.GetDatabasePassword())
	req.Header.Set("X-Database-Host", data.GetDatabaseHost())
	req.Header.Set("X-Database-Port", fmt.Sprintf("%d", data.GetDatabasePort()))
	req.Header.Set("X-Database-Name", data.GetDatabaseName())
	req.Header.Set("X-User-Id", data.GetUserId())
	req.Header.Set("X-Username", data.GetUsername())
	req.Header.Set("X-Business-Unit-Id", data.GetBusinessUnitId())
	req.Header.Set("X-Tenant-Id", data.GetTenantId())
	req.Header.Set("X-Group-Id", data.GetGroupId())
	req.Header.Set("X-Level", data.GetLevel())
	req.Header.Set("X-Token", token)
}

func main() {}
