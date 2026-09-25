package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arcelo/rtbh-panel/internal/agentrpc"
	"github.com/arcelo/rtbh-panel/internal/bgpengine"
	"github.com/arcelo/rtbh-panel/internal/dashboard"
	"github.com/arcelo/rtbh-panel/internal/feed"
	"github.com/arcelo/rtbh-panel/internal/policystore"
	"github.com/arcelo/rtbh-panel/internal/sqlstore"
	webui "github.com/arcelo/rtbh-panel/web"
)

type Engine interface {
	Start(context.Context) error
	Stop(context.Context) error
	Status(context.Context) (bgpengine.Status, error)
	Announce(bgpengine.Route) error
	Withdraw(bgpengine.Route) error
}

type Server struct {
	config     Config
	engine     Engine
	store      *policystore.Store
	sqlStore   *sqlstore.SQLStore
	queue      *policyQueue
	controller *policyController
	feedMgr    *feed.Manager

	started  chan struct{}
	once     sync.Once
	cursor   uint64
	mu       sync.RWMutex
	httpAddr string
	syncAddr string
}

func NewServer(config Config) (*Server, error) {
	if err := config.validateCommon(); err != nil {
		return nil, err
	}
	if err := config.validateServer(); err != nil {
		return nil, err
	}
	host, portRaw, err := net.SplitHostPort(config.BGPListenAddress)
	if err != nil {
		return nil, fmt.Errorf("runtime: BGP listen: %w", err)
	}
	port, err := strconv.ParseInt(portRaw, 10, 32)
	if err != nil || port < -1 || port == 0 || port > 65535 {
		return nil, errors.New("runtime: BGP port must be -1 or between 1 and 65535")
	}
	engine, err := bgpengine.New(bgpengine.Config{
		LocalASN:        config.LocalASN,
		RouterID:        config.RouterID,
		ListenAddresses: []string{host},
		ListenPort:      int32(port),
		ListenRanges:    config.ListenRanges,
		AllowedASNs:     config.AllowedASNs,
		MaxSessions:     config.MaxSessions,
	})
	if err != nil {
		return nil, fmt.Errorf("runtime: create BGP engine: %w", err)
	}
	var store *policystore.Store
	if config.PolicyFile == "" {
		store = policystore.New()
	} else if strings.HasSuffix(config.PolicyFile, ".db") || strings.HasSuffix(config.PolicyFile, ".sqlite") {
		store = policystore.New()
		if config.DBDriver == "" {
			config.DBDriver = "sqlite"
			config.DBDSN = config.PolicyFile
		}
	} else {
		store, err = policystore.Open(config.PolicyFile)
		if err != nil {
			return nil, fmt.Errorf("runtime: open policy store: %w", err)
		}
	}

	var sqlStore *sqlstore.SQLStore
	if config.DBDriver != "" {
		dsn := config.DBDSN
		if dsn == "" {
			dsn = "policy.db"
		}
		var err error
		sqlStore, err = sqlstore.Open(config.DBDriver, dsn)
		if err != nil {
			return nil, fmt.Errorf("runtime: open sql store (%s): %w", config.DBDriver, err)
		}
	}

	cursor, err := loadCursor(config.CursorFile)
	if err != nil {
		return nil, err
	}
	controller := newPolicyController(store, sqlStore, engine, config.DryRun, config.RTBHNextHopV4, config.RTBHNextHopV6, nil)
	if !config.RTBHNextHopV4.IsValid() {
		controller.nextHopV4 = config.RouterID
	}

	feedFile := ""
	if config.PolicyFile != "" {
		feedFile = config.PolicyFile + ".feeds.json"
	}
	feedMgr, err := feed.OpenManager(feedFile,
		func(ctx context.Context, sf feed.FeedSource, toAdd, toRemove []string) error {
			if sf.List != "blocklist" && sf.List != "whitelist" {
				return nil
			}
			return controller.ApplyBatch(ctx, sf.List, toAdd, toRemove)
		},
		func(ctx context.Context, sf feed.FeedSource, prefixes []string) error {
			if sf.List != "blocklist" && sf.List != "whitelist" {
				return nil
			}
			return controller.ApplyBatch(ctx, sf.List, nil, prefixes)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("runtime: open feed manager: %w", err)
	}
	if config.BlocklistFeed != "" {
		_, _ = feedMgr.Save(feed.FeedSource{
			Name:          "Default Blocklist",
			List:          "blocklist",
			URL:           config.BlocklistFeed,
			Interval:      config.FeedInterval,
			Enabled:       true,
			ExpandSubnets: false,
		})
	}
	if config.WhitelistFeed != "" {
		_, _ = feedMgr.Save(feed.FeedSource{
			Name:          "Default Whitelist",
			List:          "whitelist",
			URL:           config.WhitelistFeed,
			Interval:      config.FeedInterval,
			Enabled:       true,
			ExpandSubnets: config.WhitelistExpandSlash24,
		})
	}

	return &Server{config: config, engine: engine, store: store, sqlStore: sqlStore, queue: newPolicyQueue(), controller: controller, cursor: cursor, feedMgr: feedMgr, started: make(chan struct{})}, nil
}

func (s *Server) Started() <-chan struct{} { return s.started }

func (s *Server) HTTPAddress() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.httpAddr
}

func (s *Server) SyncAddress() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.syncAddr
}

func (s *Server) Run(ctx context.Context) error {
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	if err := s.engine.Start(ctx); err != nil {
		return fmt.Errorf("runtime: start BGP engine: %w", err)
	}
	s.controller.publish = s.queue.publish
	if err := s.controller.Reconcile(time.Now()); err != nil {
		return errors.Join(fmt.Errorf("runtime: reconcile RTBH routes: %w", err), s.engine.Stop(context.Background()))
	}
	httpListener, err := net.Listen("tcp", s.config.HTTPListenAddress)
	if err != nil {
		return errors.Join(fmt.Errorf("runtime: dashboard listen: %w", err), s.engine.Stop(context.Background()))
	}
	syncListener, err := net.Listen("tcp", s.config.SyncListenAddress)
	if err != nil {
		return errors.Join(fmt.Errorf("runtime: policy-sync listen: %w", err), httpListener.Close(), s.engine.Stop(context.Background()))
	}

	s.mu.Lock()
	s.httpAddr = httpListener.Addr().String()
	s.syncAddr = syncListener.Addr().String()
	s.mu.Unlock()
	httpServer := &http.Server{
		Handler: dashboard.NewHandler(&dashboardBackend{
			config:     s.config,
			engine:     s.engine,
			store:      s.store,
			sqlStore:   s.sqlStore,
			publish:    s.queue.publish,
			controller: s.controller,
			feedMgr:    s.feedMgr,
		}, func(*http.Request) bool { return true }, webui.Dist()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 4)
	var workers sync.WaitGroup
	go func() { errCh <- normalizeServerError(httpServer.Serve(httpListener)) }()
	go func() { errCh <- s.acceptSync(runCtx, syncListener, &workers) }()
	if !s.config.DryRun {
		go func() { errCh <- s.controller.RunExpiry(runCtx) }()
	}
	if s.feedMgr != nil {
		go func() { errCh <- s.feedMgr.Run(runCtx) }()
	}
	s.once.Do(func() { close(s.started) })

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}
	cancelRun()
	if err := syncListener.Close(); runErr == nil && err != nil && !errors.Is(err, net.ErrClosed) {
		runErr = fmt.Errorf("runtime: close policy-sync listener: %w", err)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); runErr == nil && err != nil {
		runErr = fmt.Errorf("runtime: shutdown dashboard: %w", err)
	}
	workers.Wait()
	if err := s.engine.Stop(shutdownCtx); runErr == nil && err != nil {
		runErr = fmt.Errorf("runtime: stop BGP engine: %w", err)
	}
	return runErr
}

func (s *Server) acceptSync(ctx context.Context, listener net.Listener, workers *sync.WaitGroup) error {
	var active net.Conn
	var cancelActive context.CancelFunc
	var activeDone chan struct{}
	closeActive := func() {
		if cancelActive == nil {
			return
		}
		cancelActive()
		_ = active.Close()
		<-activeDone
		active = nil
		cancelActive = nil
		activeDone = nil
	}
	defer closeActive()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("runtime: policy-sync accept: %w", err)
		}
		closeActive()
		connectionCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		active = connection
		cancelActive = cancel
		activeDone = done
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer close(done)
			defer connection.Close()
			_ = s.handleSync(connectionCtx, connection)
		}()
	}
}

func (s *Server) handleSync(ctx context.Context, connection net.Conn) error {
	session, err := agentrpc.NewSession(connection, agentrpc.Config{MaxMessageBytes: s.config.SyncMaxMessageBytes, MaxInFlight: s.config.SyncMaxInFlight}, agentrpc.Resume{PeerCursor: s.cursor})
	if err != nil {
		return fmt.Errorf("runtime: create policy-sync session: %w", err)
	}
	for {
		change, err := s.queue.next(ctx)
		if err != nil {
			return err
		}
		sequence, err := session.SendPolicy(ctx, change)
		if err != nil {
			return fmt.Errorf("runtime: send synced policy: %w", err)
		}
		message, err := session.Receive(ctx)
		if err != nil {
			return fmt.Errorf("runtime: receive policy ACK: %w", err)
		}
		if message.Type != agentrpc.TypeACK || message.Cursor < sequence {
			return fmt.Errorf("runtime: invalid policy ACK for sequence %d", sequence)
		}
		if err := saveCursor(s.config.CursorFile, message.Cursor); err != nil {
			return err
		}
		s.cursor = message.Cursor
		s.queue.commit(change)
	}
}

func normalizeServerError(err error) error {
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
