package oidc

const (
	ErrorInvalidRequest          = "invalid_request"           // 请求缺少必需的参数、包含无效的参数值、包含重复参数或格式不正确。
	ErrorUnauthorizedClient      = "unauthorized_client"       // 客户端未被授权使用此方法请求授权码
	ErrorAccessDenied            = "access_denied"             // 资源所有者或授权服务器拒绝该请求
	ErrorUnsupportedResponseType = "unsupported_response_type" // 授权服务器不支持使用此方法获得授权码
	ErrorInvalidScope            = "invalid_scope"             // 请求的范围无效，未知的或格式不正确
	ErrorServer                  = "server_error"              // 授权服务器遇到意外情况，无法满足请求。（之所以需要此错误代码，是因为无法通过 HTTP 重定向将 500 内部服务器错误 HTTP 状态代码返回给客户端。）
	ErrorTemporarilyUnavailable  = "temporarily_unavailable"   // 由于服务器临时超载或维护，授权服务器当前无法处理请求。（需要此错误代码，因为无法通过 HTTP 重定向将 503 服务不可用的 HTTP 状态代码返回给客户端。）
)
