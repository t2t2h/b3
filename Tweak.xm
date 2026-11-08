// DomainSniffer - يسجّل النطاقات والـ IP التي يتصل بها التطبيق ويعرضها في قائمة عائمة.
// لا يعدّل أي سلوك في اللعبة، يراقب فقط.

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <substrate.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#pragma mark - Store

@interface DSStore : NSObject
+ (instancetype)shared;
- (void)recordHost:(NSString *)host ips:(NSArray<NSString *> *)ips source:(NSString *)src failed:(BOOL)failed;
- (void)recordIP:(NSString *)ip port:(int)port source:(NSString *)src;
- (NSArray<NSDictionary *> *)snapshot;
- (NSArray<NSURL *> *)saveAll;
- (NSString *)denylistText;
- (NSUInteger)denylistCount;
- (void)clear;
@end

static BOOL DSIsIPString(NSString *s) {
    struct in_addr a4; struct in6_addr a6;
    return inet_pton(AF_INET, s.UTF8String, &a4) == 1 || inet_pton(AF_INET6, s.UTF8String, &a6) == 1;
}

static NSString *DSDir(void) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *dir = [docs stringByAppendingPathComponent:@"DomainSniffer"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return dir;
}

@implementation DSStore {
    dispatch_queue_t _q;
    NSMutableDictionary<NSString *, NSMutableDictionary *> *_items;
    NSMutableDictionary<NSString *, NSString *> *_ipHost;
    NSMutableSet<NSString *> *_seenIP;
    BOOL _saveScheduled;
}

+ (instancetype)shared {
    static DSStore *s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [DSStore new]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        _q = dispatch_queue_create("ds.store", DISPATCH_QUEUE_SERIAL);
        _items = [NSMutableDictionary dictionary];
        _ipHost = [NSMutableDictionary dictionary];
        _seenIP = [NSMutableSet set];
        [self load];
    }
    return self;
}

- (NSMutableDictionary *)entryFor:(NSString *)v type:(NSString *)t {
    NSMutableDictionary *e = _items[v];
    if (!e) {
        e = [@{ @"type": t, @"count": @0, @"related": [NSMutableSet set], @"src": [NSMutableSet set],
                @"status": @"OK", @"first": @([[NSDate date] timeIntervalSince1970]), @"last": @0 } mutableCopy];
        _items[v] = e;
    }
    e[@"last"] = @([[NSDate date] timeIntervalSince1970]);
    return e;
}

- (void)recordHost:(NSString *)host ips:(NSArray<NSString *> *)ips source:(NSString *)src failed:(BOOL)failed {
    if (host.length == 0) return;
    host = host.lowercaseString;
    if (DSIsIPString(host)) { [self recordIP:host port:0 source:src]; return; }
    dispatch_async(_q, ^{
        NSMutableDictionary *e = [self entryFor:host type:@"domain"];
        e[@"count"] = @([e[@"count"] integerValue] + 1);
        [e[@"src"] addObject:src];
        BOOL blocked = NO;
        for (NSString *ip in ips) {
            [e[@"related"] addObject:ip];
            self->_ipHost[ip] = host;
            if ([ip isEqualToString:@"0.0.0.0"] || [ip isEqualToString:@"::"]) blocked = YES;
        }
        if (blocked) e[@"status"] = @"BLOCKED";
        else if (failed && ips.count == 0) e[@"status"] = @"FAILED";
        else if (ips.count > 0) e[@"status"] = @"OK";
        [self markDirty];
    });
}

- (void)recordIP:(NSString *)ip port:(int)port source:(NSString *)src {
    if (ip.length == 0) return;
    NSString *key = [NSString stringWithFormat:@"%@:%d", ip, port];
    @synchronized (_seenIP) {
        if ([_seenIP containsObject:key]) return;
        [_seenIP addObject:key];
    }
    dispatch_async(_q, ^{
        NSMutableDictionary *e = [self entryFor:ip type:@"ip"];
        e[@"count"] = @([e[@"count"] integerValue] + 1);
        [e[@"src"] addObject:(port ? [NSString stringWithFormat:@"%@:%d", src, port] : src)];
        NSString *h = self->_ipHost[ip];
        if (h) [e[@"related"] addObject:h];
        [self markDirty];
    });
}

- (void)markDirty {  // يُستدعى داخل _q
    if (_saveScheduled) return;
    _saveScheduled = YES;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), _q, ^{
        self->_saveScheduled = NO;
        [self writeJSON];
    });
}

- (NSArray *)sorted:(id)set { return [[set allObjects] sortedArrayUsingSelector:@selector(compare:)]; }

- (NSArray<NSDictionary *> *)snapshot {
    __block NSMutableArray *out = [NSMutableArray array];
    dispatch_sync(_q, ^{
        for (NSString *k in self->_items) {
            NSDictionary *e = self->_items[k];
            [out addObject:@{ @"value": k, @"type": e[@"type"], @"count": e[@"count"],
                              @"related": [self sorted:e[@"related"]], @"src": [self sorted:e[@"src"]],
                              @"status": e[@"status"], @"last": e[@"last"], @"first": e[@"first"] }];
        }
    });
    [out sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [b[@"last"] compare:a[@"last"]];
    }];
    return out;
}

- (void)writeJSON {  // داخل _q
    NSMutableDictionary *dump = [NSMutableDictionary dictionary];
    for (NSString *k in _items) {
        NSDictionary *e = _items[k];
        dump[k] = @{ @"type": e[@"type"], @"count": e[@"count"], @"related": [self sorted:e[@"related"]],
                     @"src": [self sorted:e[@"src"]], @"status": e[@"status"], @"first": e[@"first"], @"last": e[@"last"] };
    }
    NSData *d = [NSJSONSerialization dataWithJSONObject:dump options:NSJSONWritingPrettyPrinted error:nil];
    [d writeToFile:[DSDir() stringByAppendingPathComponent:@"data.json"] atomically:YES];
}

- (void)load {
    NSData *d = [NSData dataWithContentsOfFile:[DSDir() stringByAppendingPathComponent:@"data.json"]];
    if (!d) return;
    NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if (![j isKindOfClass:NSDictionary.class]) return;
    for (NSString *k in j) {
        NSDictionary *e = j[k];
        _items[k] = [@{ @"type": e[@"type"] ?: @"domain", @"count": e[@"count"] ?: @0,
                        @"related": [NSMutableSet setWithArray:e[@"related"] ?: @[]],
                        @"src": [NSMutableSet setWithArray:e[@"src"] ?: @[]],
                        @"status": e[@"status"] ?: @"OK", @"first": e[@"first"] ?: @0, @"last": e[@"last"] ?: @0 } mutableCopy];
    }
}

- (NSString *)denylistText {
    NSMutableArray *lines = [NSMutableArray array];
    for (NSDictionary *e in [self snapshot]) {
        if ([e[@"type"] isEqualToString:@"domain"] && ![e[@"status"] isEqualToString:@"BLOCKED"]) [lines addObject:e[@"value"]];
    }
    [lines sortUsingSelector:@selector(compare:)];
    return [lines componentsJoinedByString:@"\n"];
}

- (NSUInteger)denylistCount {
    NSString *t = [self denylistText];
    return t.length ? [t componentsSeparatedByString:@"\n"].count : 0;
}

- (NSArray<NSURL *> *)saveAll {
    NSArray *snap = [self snapshot];
    NSMutableArray *doms = [NSMutableArray array], *ips = [NSMutableArray array];
    for (NSDictionary *e in snap) {
        NSString *line = [NSString stringWithFormat:@"%@  [%@] x%@  %@", e[@"value"], e[@"status"], e[@"count"],
                          [e[@"related"] componentsJoinedByString:@","]];
        [([e[@"type"] isEqualToString:@"domain"] ? doms : ips) addObject:line];
    }
    [doms sortUsingSelector:@selector(compare:)]; [ips sortUsingSelector:@selector(compare:)];
    NSString *dir = DSDir();
    NSString *p1 = [dir stringByAppendingPathComponent:@"domains.txt"];
    NSString *p2 = [dir stringByAppendingPathComponent:@"ips.txt"];
    NSString *p3 = [dir stringByAppendingPathComponent:@"denylist_nextdns.txt"];
    [[doms componentsJoinedByString:@"\n"] writeToFile:p1 atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [[ips componentsJoinedByString:@"\n"] writeToFile:p2 atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [[self denylistText] writeToFile:p3 atomically:YES encoding:NSUTF8StringEncoding error:nil];
    dispatch_sync(_q, ^{ [self writeJSON]; });
    return @[ [NSURL fileURLWithPath:p3], [NSURL fileURLWithPath:p1], [NSURL fileURLWithPath:p2],
              [NSURL fileURLWithPath:[dir stringByAppendingPathComponent:@"data.json"]] ];
}

- (void)clear {
    dispatch_sync(_q, ^{
        [self->_items removeAllObjects]; [self->_ipHost removeAllObjects];
        [self writeJSON];
    });
    @synchronized (_seenIP) { [_seenIP removeAllObjects]; }
}
@end

#pragma mark - Network hooks

static NSString *DSAddrString(const struct sockaddr *sa) {
    char buf[INET6_ADDRSTRLEN];
    if (!sa) return nil;
    if (sa->sa_family == AF_INET) {
        if (inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, buf, sizeof buf)) return @(buf);
    } else if (sa->sa_family == AF_INET6) {
        if (inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr, buf, sizeof buf)) return @(buf);
    }
    return nil;
}

static void DSNoteSockaddr(const struct sockaddr *sa, socklen_t len, const char *src) {
    if (!sa || len == 0 || len > sizeof(struct sockaddr_storage)) return;
    static __thread struct sockaddr_storage last;
    static __thread socklen_t lastLen;
    if (lastLen == len && memcmp(&last, sa, len) == 0) return;
    memcpy(&last, sa, len); lastLen = len;

    int port = 0;
    if (sa->sa_family == AF_INET) port = ntohs(((const struct sockaddr_in *)sa)->sin_port);
    else if (sa->sa_family == AF_INET6) port = ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
    else return;
    NSString *ip = DSAddrString(sa);
    if (!ip || [ip isEqualToString:@"127.0.0.1"] || [ip isEqualToString:@"::1"] || [ip isEqualToString:@"0.0.0.0"] || [ip isEqualToString:@"::"]) return;
    [[DSStore shared] recordIP:ip port:port source:@(src)];
}

static int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static int hook_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    int r = orig_getaddrinfo(node, service, hints, res);
    if (node) {
        NSMutableArray *ips = [NSMutableArray array];
        if (r == 0 && res && *res) {
            for (struct addrinfo *p = *res; p; p = p->ai_next) {
                NSString *s = DSAddrString(p->ai_addr);
                if (s && ![ips containsObject:s]) [ips addObject:s];
            }
        }
        NSString *h = [NSString stringWithUTF8String:node];
        if (h) [[DSStore shared] recordHost:h ips:ips source:@"dns" failed:(r != 0)];
    }
    return r;
}

static struct hostent *(*orig_gethostbyname)(const char *);
static struct hostent *hook_gethostbyname(const char *name) {
    struct hostent *r = orig_gethostbyname(name);
    if (name) {
        NSString *h = [NSString stringWithUTF8String:name];
        if (h) [[DSStore shared] recordHost:h ips:nil source:@"dns" failed:(r == NULL)];
    }
    return r;
}

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static int hook_connect(int fd, const struct sockaddr *sa, socklen_t len) {
    DSNoteSockaddr(sa, len, "connect");
    return orig_connect(fd, sa, len);
}

static ssize_t (*orig_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t hook_sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *dst, socklen_t dlen) {
    if (dst) DSNoteSockaddr(dst, dlen, "udp");
    return orig_sendto(fd, buf, n, flags, dst, dlen);
}

static void DSURL(NSURL *u, NSString *src) {
    NSString *h = u.host;
    if (h.length) [[DSStore shared] recordHost:h ips:nil source:src failed:NO];
}

%hook NSURLSession
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)r { DSURL(r.URL, @"http"); return %orig; }
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)r completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))h { DSURL(r.URL, @"http"); return %orig; }
- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)u { DSURL(u, @"http"); return %orig; }
- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)u completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))h { DSURL(u, @"http"); return %orig; }
- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)r fromData:(NSData *)d { DSURL(r.URL, @"upload"); return %orig; }
- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)r fromData:(NSData *)d completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))h { DSURL(r.URL, @"upload"); return %orig; }
- (NSURLSessionDownloadTask *)downloadTaskWithRequest:(NSURLRequest *)r { DSURL(r.URL, @"download"); return %orig; }
- (NSURLSessionDownloadTask *)downloadTaskWithURL:(NSURL *)u { DSURL(u, @"download"); return %orig; }
- (NSURLSessionWebSocketTask *)webSocketTaskWithURL:(NSURL *)u { DSURL(u, @"ws"); return %orig; }
- (NSURLSessionWebSocketTask *)webSocketTaskWithRequest:(NSURLRequest *)r { DSURL(r.URL, @"ws"); return %orig; }
%end

#pragma mark - UI

@interface DSMenuVC : UIViewController <UITableViewDataSource, UITableViewDelegate, UISearchBarDelegate>
@end

@implementation DSMenuVC {
    UITableView *_tv; UISearchBar *_sb; UISegmentedControl *_seg; UILabel *_title; UILabel *_toast;
    NSArray<NSDictionary *> *_data; NSString *_query; NSTimer *_timer;
}

- (UIButton *)btn:(NSString *)t sel:(SEL)s {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    [b setTitle:t forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    [b addTarget:self action:s forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;

    _title = [UILabel new];
    _title.font = [UIFont boldSystemFontOfSize:18];
    UIStackView *top = [[UIStackView alloc] initWithArrangedSubviews:@[_title, [self btn:@"إغلاق" sel:@selector(closeTap)]]];
    top.distribution = UIStackViewDistributionEqualSpacing;

    _sb = [UISearchBar new];
    _sb.delegate = self; _sb.placeholder = @"بحث عن نطاق أو IP"; _sb.searchBarStyle = UISearchBarStyleMinimal;
    _sb.autocapitalizationType = UITextAutocapitalizationTypeNone;

    _seg = [[UISegmentedControl alloc] initWithItems:@[@"الكل", @"نطاقات", @"IP", @"محجوب"]];
    _seg.selectedSegmentIndex = 0;
    [_seg addTarget:self action:@selector(reload) forControlEvents:UIControlEventValueChanged];

    _tv = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStylePlain];
    _tv.dataSource = self; _tv.delegate = self;
    _tv.rowHeight = UITableViewAutomaticDimension; _tv.estimatedRowHeight = 64;

    UIStackView *bottom = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self btn:@"💾 حفظ" sel:@selector(saveTap)], [self btn:@"📤 مشاركة" sel:@selector(shareTap:)],
        [self btn:@"📋 نسخ Denylist" sel:@selector(copyTap)], [self btn:@"🗑 مسح" sel:@selector(clearTap)]]];
    bottom.distribution = UIStackViewDistributionFillEqually;

    UIStackView *main = [[UIStackView alloc] initWithArrangedSubviews:@[top, _sb, _seg, _tv, bottom]];
    main.axis = UILayoutConstraintAxisVertical; main.spacing = 8;
    main.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:main];
    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [main.topAnchor constraintEqualToAnchor:g.topAnchor constant:12],
        [main.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-8],
        [main.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:12],
        [main.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-12]]];

    _toast = [UILabel new];
    _toast.backgroundColor = [UIColor.blackColor colorWithAlphaComponent:0.8];
    _toast.textColor = UIColor.whiteColor; _toast.textAlignment = NSTextAlignmentCenter;
    _toast.font = [UIFont systemFontOfSize:13]; _toast.layer.cornerRadius = 10; _toast.clipsToBounds = YES;
    _toast.alpha = 0; _toast.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_toast];
    [NSLayoutConstraint activateConstraints:@[
        [_toast.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [_toast.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-60],
        [_toast.widthAnchor constraintGreaterThanOrEqualToConstant:160],
        [_toast.heightAnchor constraintEqualToConstant:34]]];
    [self reload];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    _timer = [NSTimer scheduledTimerWithTimeInterval:1.5 target:self selector:@selector(reload) userInfo:nil repeats:YES];
}
- (void)viewDidDisappear:(BOOL)animated { [super viewDidDisappear:animated]; [_timer invalidate]; _timer = nil; }

- (void)reload {
    NSInteger m = _seg.selectedSegmentIndex;
    NSString *q = _query.lowercaseString;
    NSMutableArray *out = [NSMutableArray array];
    for (NSDictionary *e in [[DSStore shared] snapshot]) {
        if (m == 1 && ![e[@"type"] isEqualToString:@"domain"]) continue;
        if (m == 2 && ![e[@"type"] isEqualToString:@"ip"]) continue;
        if (m == 3 && ![e[@"status"] isEqualToString:@"BLOCKED"]) continue;
        if (q.length) {
            NSString *hay = [[NSString stringWithFormat:@"%@ %@", e[@"value"], [e[@"related"] componentsJoinedByString:@" "]] lowercaseString];
            if (![hay containsString:q]) continue;
        }
        [out addObject:e];
    }
    _data = out;
    _title.text = [NSString stringWithFormat:@"🌐 Domain Sniffer (%lu)", (unsigned long)out.count];
    [_tv reloadData];
}

- (void)toast:(NSString *)t {
    _toast.text = [NSString stringWithFormat:@"  %@  ", t];
    [UIView animateWithDuration:0.2 animations:^{ self->_toast.alpha = 1; } completion:^(BOOL f) {
        [UIView animateWithDuration:0.3 delay:1.4 options:0 animations:^{ self->_toast.alpha = 0; } completion:nil];
    }];
}

- (void)closeTap { [self dismissViewControllerAnimated:YES completion:nil]; }

- (void)saveTap {
    [[DSStore shared] saveAll];
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"تم الحفظ ✅"
        message:@"Documents/DomainSniffer/\n• denylist_nextdns.txt\n• domains.txt\n• ips.txt\n• data.json\n\nاستخدم زر مشاركة لحفظها في تطبيق الملفات."
        preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"حسناً" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

- (void)shareTap:(UIButton *)sender {
    NSArray *urls = [[DSStore shared] saveAll];
    UIActivityViewController *vc = [[UIActivityViewController alloc] initWithActivityItems:urls applicationActivities:nil];
    vc.popoverPresentationController.sourceView = sender;
    vc.popoverPresentationController.sourceRect = sender.bounds;
    [self presentViewController:vc animated:YES completion:nil];
}

- (void)copyTap {
    UIPasteboard.generalPasteboard.string = [[DSStore shared] denylistText];
    [self toast:[NSString stringWithFormat:@"تم نسخ %lu نطاق", (unsigned long)[[DSStore shared] denylistCount]]];
}

- (void)clearTap {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"مسح كل السجل؟" message:nil preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"إلغاء" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"مسح" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *x) {
        [[DSStore shared] clear]; [self reload];
    }]];
    [self presentViewController:a animated:YES completion:nil];
}

- (void)searchBar:(UISearchBar *)s textDidChange:(NSString *)t { _query = t; [self reload]; }
- (void)searchBarSearchButtonClicked:(UISearchBar *)s { [s resignFirstResponder]; }

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return _data.count; }

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:@"c"];
    if (!c) c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"c"];
    NSDictionary *e = _data[ip.row];
    NSString *st = e[@"status"];
    NSString *badge = [st isEqualToString:@"BLOCKED"] ? @"⛔ " : ([st isEqualToString:@"FAILED"] ? @"⚠️ " : @"");
    c.textLabel.text = [badge stringByAppendingString:e[@"value"]];
    c.textLabel.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightSemibold];
    NSArray *rel = e[@"related"];
    NSArray *shown = rel.count > 4 ? [rel subarrayWithRange:NSMakeRange(0, 4)] : rel;
    c.detailTextLabel.text = [NSString stringWithFormat:@"×%@ • %@%@", e[@"count"], [e[@"src"] componentsJoinedByString:@", "],
                              shown.count ? [@"\n" stringByAppendingString:[shown componentsJoinedByString:@", "]] : @""];
    c.detailTextLabel.numberOfLines = 3;
    c.detailTextLabel.textColor = UIColor.secondaryLabelColor;
    return c;
}

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    UIPasteboard.generalPasteboard.string = _data[ip.row][@"value"];
    [self toast:@"تم النسخ"];
}
@end

@interface DSPassWindow : UIWindow
@end
@implementation DSPassWindow
- (UIView *)hitTest:(CGPoint)p withEvent:(UIEvent *)e {
    UIView *v = [super hitTest:p withEvent:e];
    return (v == self.rootViewController.view || v == self) ? nil : v;
}
@end

@interface DSRootVC : UIViewController
@end
@implementation DSRootVC {
    UIButton *_fab;
}
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.clearColor;
    _fab = [UIButton buttonWithType:UIButtonTypeSystem];
    _fab.frame = CGRectMake(16, 140, 48, 48);
    _fab.backgroundColor = [[UIColor systemBlueColor] colorWithAlphaComponent:0.85];
    _fab.layer.cornerRadius = 24;
    [_fab setTitle:@"🌐" forState:UIControlStateNormal];
    _fab.titleLabel.font = [UIFont systemFontOfSize:22];
    [_fab addTarget:self action:@selector(open) forControlEvents:UIControlEventTouchUpInside];
    [_fab addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(pan:)]];
    [self.view addSubview:_fab];
}
- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGRect b = self.view.bounds; CGPoint c = _fab.center;
    c.x = MIN(MAX(c.x, 24), b.size.width - 24); c.y = MIN(MAX(c.y, 24), b.size.height - 24);
    _fab.center = c;
}
- (void)pan:(UIPanGestureRecognizer *)g {
    CGPoint t = [g translationInView:self.view];
    _fab.center = CGPointMake(_fab.center.x + t.x, _fab.center.y + t.y);
    [g setTranslation:CGPointZero inView:self.view];
    [self.view setNeedsLayout];
}
- (void)open {
    if (self.presentedViewController) return;
    [self presentViewController:[DSMenuVC new] animated:YES completion:nil];
}
@end

static DSPassWindow *gWindow;

static void DSShow(void) {
    if (gWindow) return;
    UIWindowScene *scene = nil;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if ([s isKindOfClass:UIWindowScene.class] && s.activationState == UISceneActivationStateForegroundActive) {
            scene = (UIWindowScene *)s; break;
        }
    }
    DSPassWindow *w = scene ? [[DSPassWindow alloc] initWithWindowScene:scene]
                            : [[DSPassWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    w.windowLevel = UIWindowLevelAlert + 100;
    w.backgroundColor = UIColor.clearColor;
    w.rootViewController = [DSRootVC new];
    w.hidden = NO;
    gWindow = w;
}

%ctor {
    @autoreleasepool {
        [DSStore shared];
        MSHookFunction((void *)getaddrinfo, (void *)hook_getaddrinfo, (void **)&orig_getaddrinfo);
        MSHookFunction((void *)gethostbyname, (void *)hook_gethostbyname, (void **)&orig_gethostbyname);
        MSHookFunction((void *)connect, (void *)hook_connect, (void **)&orig_connect);
        MSHookFunction((void *)sendto, (void *)hook_sendto, (void **)&orig_sendto);
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification object:nil
            queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *n) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{ DSShow(); });
        }];
    }
}
