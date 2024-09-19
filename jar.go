//版权所有 2012 The Go 作者。版权所有。
//此源代码的使用受 BSD 风格的约束
//可以在 LICENSE 文件中找到的许可证。

// cookiejar 包实现了内存中符合 RFC 6265 的 http.CookieJar。
//
// 这个实现是 net/http/cookiejar 的一个分支，它也
// 实现将 cookie 转储到持久化的方法
// 存储和检索它们。
package cookiejar

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
	"gopkg.in/errgo.v1"
)

// PublicSuffixList 提供域的公共后缀。例如：
// -“example.com”的公共后缀是“com”，
// -“foo1.foo2.foo3.co.uk”的公共后缀是“co.uk”，并且
// -“bar.pvt.k12.ma.us”的公共后缀是“pvt.k12.ma.us”。
//
// PublicSuffixList 的实现必须对于并发使用是安全的
// 多个 goroutine。
//
// 始终返回“”的实现是有效的并且可能对
// 测试但不安全：这意味着 foo.com 的 HTTP 服务器可以
// 为 bar.com 设置 cookie。
//
// 包中包含公共后缀列表实现
// golang.org/x/net/publicsuffix。
type PublicSuffixList interface {
	//PublicSuffix 返回域的公共后缀。
	//
	//TODO: 指定调用者和被调用者中的哪一个负责 IP
	//地址，前导点和尾随点，区分大小写，以及
	//对于 IDN/Punycode。
	PublicSuffix(domain string) string

	//String 返回此公共后缀来源的描述
	//列表。描述通常会包含诸如时间之类的内容
	//标记或版本号。
	String() string
}

// Options 是创建新 Jar 的选项。
type Options struct {
	//PublicSuffixList为公共后缀列表，判断是否
	//HTTP 服务器可以为域设置 cookie。
	//
	//如果为 nil，则为 golang.org/x/net/publicsuffix 中的公共后缀列表实现
	//被使用。
	PublicSuffixList PublicSuffixList

	//Filename 保存用于存储 cookie 的文件。
	//如果为空，则使用 DefaultCookieFile 的值。
	Filename string

	//NoPersist 指定是否不应该使用持久性
	//（对于测试有用）。如果这是真的，文件名的值将是
	//被忽略。
	NoPersist bool
}

// Jar 实现了 net/http 包中的 http.CookieJar 接口。
type Jar struct {
	// filename 保存加载 cookie 的文件。
	filename string

	psList PublicSuffixList

	// mu locks the remaining fields.
	mu sync.Mutex

	//条目是一组条目，由其 eTLD+1 指定密钥并由
	//他们的名称/域/路径。
	entries map[string]map[string]entry
}

var noOptions Options

// New 返回一个新的 cookie jar。 nil *Options 相当于零
// 选项。
//
// 如果 cookie 无法加载，New 将返回错误
// 出于任何原因从文件中读取，而不是文件不存在。
func New(o *Options) (*Jar, error) {
	return newAtTime(o, time.Now())
}

// newAtTime 与 New 类似，但将当前时间作为参数。
func newAtTime(o *Options, now time.Time) (*Jar, error) {
	jar := &Jar{
		entries: make(map[string]map[string]entry),
	}
	if o == nil {
		o = &noOptions
	}
	if jar.psList = o.PublicSuffixList; jar.psList == nil {
		jar.psList = publicsuffix.List
	}
	if !o.NoPersist {
		if jar.filename = o.Filename; jar.filename == "" {
			jar.filename = DefaultCookieFile()
		}
		if err := jar.load(); err != nil {
			return nil, errgo.Notef(err, "cannot load cookies")
		}
	}
	jar.deleteExpired(now)
	return jar, nil
}

// homeDir 返回环境中指定的特定于操作系统的主路径。
func homeDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("HOMEDRIVE"), os.Getenv("HOMEPATH"))
	}
	return os.Getenv("HOME")
}

// entry 是 cookie 的内部表示。
//
// 此结构类型本身不在该包之外使用，但在导出的
// 字段是 RFC 6265 的字段。
// 请注意，此结构被编组为 JSON，因此向后兼容
// 应该保留。
type entry struct {
	Name       string
	Value      string
	Domain     string
	Path       string
	Secure     bool
	HttpOnly   bool
	Persistent bool
	HostOnly   bool
	Expires    time.Time
	Creation   time.Time
	LastAccess time.Time

	//cookie更新时更新记录。
	//这与创建时间不同，因为 cookie
	//可以在不更新创建时间的情况下进行更改。
	Updated time.Time

	//CanonicalHost 存储原始规范主机名
	//与 cookie 关联的。我们存储这个
	//这样即使公共后缀列表发生变化（例如
	//当存储/加载cookie时）我们仍然可以获得正确的结果
	//jar 密钥。
	CanonicalHost string
}

// id 返回 e 的域；路径；名称三元组作为 id。
func (e *entry) id() string {
	return id(e.Domain, e.Path, e.Name)
}

// id 返回域；路径；名称三元组作为 id。
func id(domain, path, name string) string {
	return fmt.Sprintf("%s;%s;%s", domain, path, name)
}

// shouldSend 判断 e 的 cookie 是否有资格包含在 a 中
// 请求主机/路径。调用者有责任检查是否
// cookie 已过期。
func (e *entry) shouldSend(https bool, host, path string) bool {
	return e.domainMatch(host) && e.pathMatch(path) && (https || !e.Secure)
}

// domainMatch 实现 RFC 6265 第 5.1.3 节的“域匹配”。
func (e *entry) domainMatch(host string) bool {
	if e.Domain == host {
		return true
	}
	return !e.HostOnly && hasDotSuffix(host, e.Domain)
}

// pathMatch implements "path-match" according to RFC 6265 section 5.1.4.
func (e *entry) pathMatch(requestPath string) bool {
	if requestPath == e.Path {
		return true
	}
	if strings.HasPrefix(requestPath, e.Path) {
		if e.Path[len(e.Path)-1] == '/' {
			return true // The "/any/" matches "/any/path" case.
		} else if requestPath[len(e.Path)] == '/' {
			return true // The "/any" matches "/any/path" case.
		}
	}
	return false
}

// hasDotSuffix reports whether s ends in "."+suffix.
func hasDotSuffix(s, suffix string) bool {
	return len(s) > len(suffix) && s[len(s)-len(suffix)-1] == '.' && s[len(s)-len(suffix):] == suffix
}

type byCanonicalHost struct {
	byPathLength
}

func (s byCanonicalHost) Less(i, j int) bool {
	e0, e1 := &s.byPathLength[i], &s.byPathLength[j]
	if e0.CanonicalHost != e1.CanonicalHost {
		return e0.CanonicalHost < e1.CanonicalHost
	}
	return s.byPathLength.Less(i, j)
}

// byPathLength is a []entry sort.Interface that sorts according to RFC 6265
// section 5.4 point 2: by longest path and then by earliest creation time.
type byPathLength []entry

func (s byPathLength) Len() int { return len(s) }

func (s byPathLength) Less(i, j int) bool {
	e0, e1 := &s[i], &s[j]
	if len(e0.Path) != len(e1.Path) {
		return len(e0.Path) > len(e1.Path)
	}
	if !e0.Creation.Equal(e1.Creation) {
		return e0.Creation.Before(e1.Creation)
	}
	// The following are not strictly necessary
	// but are useful for providing deterministic
	// behaviour in tests.
	if e0.Name != e1.Name {
		return e0.Name < e1.Name
	}
	return e0.Value < e1.Value
}

func (s byPathLength) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// Cookies implements the Cookies method of the http.CookieJar interface.
//
// It returns an empty slice if the URL's scheme is not HTTP or HTTPS.
func (j *Jar) Cookies(u *url.URL) (cookies []*http.Cookie) {
	return j.cookies(u, time.Now())
}

// cookies 与 Cookie 类似，但将当前时间作为参数。
func (j *Jar) cookies(u *url.URL, now time.Time) (cookies []*http.Cookie) {
	if u.Scheme != "http" && u.Scheme != "https" {
		return cookies
	}
	host, err := canonicalHost(u.Host)
	if err != nil {
		return cookies
	}
	key := jarKey(host, j.psList)

	j.mu.Lock()
	defer j.mu.Unlock()

	submap := j.entries[key]
	if submap == nil {
		return cookies
	}

	https := u.Scheme == "https"
	path := u.Path
	if path == "" {
		path = "/"
	}

	var selected []entry
	for id, e := range submap {
		if !e.Expires.After(now) {
			// Save some space by deleting the value when the cookie
			// expires. We can't delete the cookie itself because then
			// we wouldn't know that the cookie had expired when
			// we merge with another cookie jar.
			if e.Value != "" {
				e.Value = ""
				submap[id] = e
			}
			continue
		}
		if !e.shouldSend(https, host, path) {
			continue
		}
		e.LastAccess = now
		submap[id] = e
		selected = append(selected, e)
	}

	sort.Sort(byPathLength(selected))
	for _, e := range selected {
		cookies = append(cookies, &http.Cookie{Name: e.Name, Value: e.Value})
	}

	return cookies
}

// AllCookies 返回 jar 中的所有 cookie。返回的cookie将
// 填写了 Domain、Expires、HttpOnly、Name、Secure、Path 和 Value
// 出去。过期的 cookie 将不会被退回。该功能不
// 修改cookie jar。
func (j *Jar) AllCookies() (cookies []*http.Cookie) {
	return j.allCookies(time.Now())
}

// allCookies 与 AllCookies 类似，但将当前时间作为参数。
func (j *Jar) allCookies(now time.Time) []*http.Cookie {
	var selected []entry
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, submap := range j.entries {
		for _, e := range submap {
			if !e.Expires.After(now) {
				// Do not return expired cookies.
				continue
			}
			selected = append(selected, e)
		}
	}

	sort.Sort(byCanonicalHost{byPathLength(selected)})
	cookies := make([]*http.Cookie, len(selected))
	for i, e := range selected {
		// Note: The returned cookies do not contain sufficient
		// information to recreate the database.
		cookies[i] = &http.Cookie{
			Name:     e.Name,
			Value:    e.Value,
			Path:     e.Path,
			Domain:   e.Domain,
			Expires:  e.Expires,
			Secure:   e.Secure,
			HttpOnly: e.HttpOnly,
		}
	}

	return cookies
}

// RemoveCookie 删除与名称、域和路径匹配的cookie
// 由 c 指定。
func (j *Jar) RemoveCookie(c *http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	id := id(c.Domain, c.Path, c.Name)
	key := jarKey(c.Domain, j.psList)
	if e, ok := j.entries[key][id]; ok {
		e.Value = ""
		e.Expires = time.Now().Add(-1 * time.Second)
		j.entries[key][id] = e
	}
}

// merge 将所有给定的条目合并到 j 中。最近更改的
// cookie 优先于旧的。
func (j *Jar) merge(entries []entry) {
	for _, e := range entries {
		if e.CanonicalHost == "" {
			continue
		}
		key := jarKey(e.CanonicalHost, j.psList)
		id := e.id()
		submap := j.entries[key]
		if submap == nil {
			j.entries[key] = map[string]entry{
				id: e,
			}
			continue
		}
		oldEntry, ok := submap[id]
		if !ok || e.Updated.After(oldEntry.Updated) {
			submap[id] = e
		}
	}
}

var expiryRemovalDuration = 24 * time.Hour

// deleteExpired 删除所有过期时间足够长的条目
// 我们实际上可以期望不存在它的外部副本
// 可能会复活死掉的 cookie。
func (j *Jar) deleteExpired(now time.Time) {
	for tld, submap := range j.entries {
		for id, e := range submap {
			if !e.Expires.After(now) && !e.Updated.Add(expiryRemovalDuration).After(now) {
				delete(submap, id)
			}
		}
		if len(submap) == 0 {
			delete(j.entries, tld)
		}
	}
}

// RemoveAllHost 从 jar 中删除为给定主机设置的所有 cookie。
func (j *Jar) RemoveAllHost(host string) {
	host, err := canonicalHost(host)
	if err != nil {
		return
	}
	key := jarKey(host, j.psList)

	j.mu.Lock()
	defer j.mu.Unlock()

	expired := time.Now().Add(-1 * time.Second)
	submap := j.entries[key]
	for id, e := range submap {
		if e.CanonicalHost == host {
			//通过删除cookie时的值来节省一些空间
			//过期。我们无法删除 cookie 本身，因为那样的话
			//我们不知道 cookie 何时过期
			//我们与另一个 cookie jar 合并。
			e.Value = ""
			e.Expires = expired
			submap[id] = e
		}
	}
}

// RemoveAll 会从罐子中删除所有 cookie。
func (j *Jar) RemoveAll() {
	expired := time.Now().Add(-1 * time.Second)
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, submap := range j.entries {
		for id, e := range submap {
			//通过删除cookie时的值来节省一些空间
			//过期。我们无法删除 cookie 本身，因为那样的话
			//我们不知道 cookie 何时过期
			//我们与另一个 cookie jar 合并。
			e.Value = ""
			e.Expires = expired
			submap[id] = e
		}
	}
}

// SetCookies 实现了 http.CookieJar 接口的 SetCookies 方法。
//
// 如果 URL 的方案不是 HTTP 或 HTTPS，则不会执行任何操作。
func (j *Jar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.setCookies(u, cookies, time.Now())
}

// setCookies 与 SetCookies 类似，但以当前时间作为参数。
func (j *Jar) setCookies(u *url.URL, cookies []*http.Cookie, now time.Time) {
	if len(cookies) == 0 {
		return
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		//TODO 这真的正确吗？发送也许会很好
		//例如，cookie 到 websocket 连接。
		return
	}
	host, err := canonicalHost(u.Host)
	if err != nil {
		return
	}
	key := jarKey(host, j.psList)
	defPath := defaultPath(u.Path)

	j.mu.Lock()
	defer j.mu.Unlock()

	submap := j.entries[key]
	for _, cookie := range cookies {
		e, err := j.newEntry(cookie, now, defPath, host)
		if err != nil {
			continue
		}
		e.CanonicalHost = host
		id := e.id()
		if submap == nil {
			submap = make(map[string]entry)
			j.entries[key] = submap
		}
		if old, ok := submap[id]; ok {
			e.Creation = old.Creation
		} else {
			e.Creation = now
		}
		e.Updated = now
		e.LastAccess = now
		submap[id] = e
	}
}

// canonicalHost 从主机中剥离端口（如果存在）并返回规范化的端口
// 主机名。
func canonicalHost(host string) (string, error) {
	var err error
	host = strings.ToLower(host)
	if hasPort(host) {
		host, _, err = net.SplitHostPort(host)
		if err != nil {
			return "", err
		}
	}
	if strings.HasSuffix(host, ".") {
		// 从完全限定的域名中去除尾随点。
		host = host[:len(host)-1]
	}
	return toASCII(host)
}

// hasPort 报告主机是否包含端口号。主机可能是主机
// 名称、IPv4 或 IPv6 地址。
func hasPort(host string) bool {
	colons := strings.Count(host, ":")
	if colons == 0 {
		return false
	}
	if colons == 1 {
		return true
	}
	return host[0] == '[' && strings.Contains(host, "]:")
}

// jarKey 返回用于 jar 的密钥。
func jarKey(host string, psl PublicSuffixList) string {
	if isIP(host) {
		return host
	}

	var i int
	if psl == nil {
		i = strings.LastIndex(host, ".")
		if i == -1 {
			return host
		}
	} else {
		suffix := psl.PublicSuffix(host)
		if suffix == host {
			return host
		}
		i = len(host) - len(suffix)
		if i <= 0 || host[i-1] != '.' {
			// The provided public suffix list psl is broken.
			// Storing cookies under host is a safe stopgap.
			return host
		}
	}
	prevDot := strings.LastIndex(host[:i-1], ".")
	return host[prevDot+1:]
}

// isIP 报告主机是否是 IP 地址。
func isIP(host string) bool {
	return net.ParseIP(host) != nil
}

// defaultPath 根据以下条件返回 URL 路径的目录部分
// RFC 6265 第 5.1.4 节。
func defaultPath(path string) string {
	if len(path) == 0 || path[0] != '/' {
		return "/" // Path is empty or malformed.
	}

	i := strings.LastIndex(path, "/") // Path starts with "/", so i != -1.
	if i == 0 {
		return "/" // Path has the form "/abc".
	}
	return path[:i] // Path is either of form "/abc/xyz" or "/abc/xyz/".
}

// newEntry 从 http.Cookie 创建一个条目 c.现在是当前
// 与 c.Expires 进行比较以确定删除 c.定义路径
// 和 host 是 URL 的默认路径和规范主机名
// c 是从接收到的。
//
// 如果返回的条目在过期时间内，则应将其删除
// 过去的。在这种情况下，e可能不完整，但调用它是有效的
// e.id（取决于 e 的名称、域和路径）。
//
// 格式错误的 c.Domain 将导致错误。
func (j *Jar) newEntry(c *http.Cookie, now time.Time, defPath, host string) (e entry, err error) {
	e.Name = c.Name
	if c.Path == "" || c.Path[0] != '/' {
		e.Path = defPath
	} else {
		e.Path = c.Path
	}

	e.Domain, e.HostOnly, err = j.domainAndType(host, c.Domain)
	if err != nil {
		return e, err
	}
	// MaxAge takes precedence over Expires.
	if c.MaxAge != 0 {
		e.Persistent = true
		e.Expires = now.Add(time.Duration(c.MaxAge) * time.Second)
		if c.MaxAge < 0 {
			return e, nil
		}
	} else if c.Expires.IsZero() {
		e.Expires = endOfTime
	} else {
		e.Persistent = true
		e.Expires = c.Expires
		if !c.Expires.After(now) {
			return e, nil
		}
	}

	e.Value = c.Value
	e.Secure = c.Secure
	e.HttpOnly = c.HttpOnly

	return e, nil
}

var (
	errIllegalDomain   = errors.New("cookiejar: illegal cookie domain attribute")
	errMalformedDomain = errors.New("cookiejar: malformed cookie domain attribute")
	errNoHostname      = errors.New("cookiejar: no host name available (IP only)")
)

// endOfTime 是会话（非持久）cookie 过期的时间。
// 这个时刻可以用大多数日期/时间格式表示（不仅仅是
// Go 的 time.Time) 并且应该在未来足够远的地方。
var endOfTime = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// 域和类型决定了 cookie 的域和主机专用属性。
func (j *Jar) domainAndType(host, domain string) (string, bool, error) {
	if domain == "" {
		//SetCookie 标头中没有任何域属性指示
		//主机cookie。
		return host, true, nil
	}

	if isIP(host) {
		//根据 RFC 6265 域匹配包括不存在
		//IP 地址。
		//TODO：这可能会像普通浏览器一样宽松。
		return "", false, errNoHostname
	}

	//从这里开始：如果 cookie 有效，则它是域 cookie（带有
	//下面是公共后缀的一个例外）。
	//请参阅 RFC 6265 第 5.2.3 节。
	if domain[0] == '.' {
		domain = domain[1:]
	}

	if len(domain) == 0 || domain[0] == '.' {
		//收到“Domain=.”或“域=..some.thing”，
		//两者都是非法的。
		return "", false, errMalformedDomain
	}
	domain = strings.ToLower(domain)

	if domain[len(domain)-1] == '.' {
		//我们收到了诸如“Domain=www.example.com.”之类的内容。
		//浏览器确实处理这些东西（实际上不同）但是
		//RFC 6265 在这里似乎很清楚（例如第 4.1.2.3 节）
		//需要拒绝。  4.1.2.3 不是规范性的，但是
		//“域匹配”(5.1.3) 和“规范化主机名”
		//(5.1.2) 是。
		return "", false, errMalformedDomain
	}

	// 请参阅 RFC 6265 第 5.3 #5 节。
	if j.psList != nil {
		if ps := j.psList.PublicSuffix(domain); ps != "" && !hasDotSuffix(domain, ps) {
			if host == domain {
				//这是 cookie 的一个例外
				//带有domain属性的是一个主机cookie。
				return host, true, nil
			}
			return "", false, errIllegalDomain
		}
	}

	//域名必须与主机域名匹配：www.mycompany.com 不能
	//为 .ourcompetitors.com 设置 cookie。
	if host != domain && !hasDotSuffix(host, domain) {
		return "", false, errIllegalDomain
	}

	return domain, false, nil
}

// DefaultCookieFile 返回要使用的默认 cookie 文件
// 用于持久化 cookie 数据。
// 以下名称将按优先级降序使用：
// -$GOCOOKIES 环境变量的值。
// -$HOME/.go-cookies
func DefaultCookieFile() string {
	if f := os.Getenv("GOCOOKIES"); f != "" {
		return f
	}
	return filepath.Join(homeDir(), ".go-cookies")
}
