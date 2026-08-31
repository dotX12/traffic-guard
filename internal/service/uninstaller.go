package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
)

const (
	ufwManagedBlockStart = "# SCANNERS-BLOCK chain - managed by antiscan"
	ufwManagedBlockEnd   = "# END SCANNERS-BLOCK"
)

// UninstallerService reverts TrafficGuard-managed system changes.
type UninstallerService struct {
	logger      zerolog.Logger
	cmdSvc      *CommandService
	iptablesCmd *IptablesCommandService
	ipsetCmd    *IpsetCommandService
}

// NewUninstallerService creates a new uninstaller service.
func NewUninstallerService(logger zerolog.Logger, cmdSvc *CommandService) *UninstallerService {
	return &UninstallerService{
		logger:      logger,
		cmdSvc:      cmdSvc,
		iptablesCmd: NewIptablesCommandService(logger, cmdSvc),
		ipsetCmd:    NewIpsetCommandService(logger, cmdSvc),
	}
}

// Uninstall removes TrafficGuard artifacts and restores firewall state.
func (s *UninstallerService) Uninstall(removeLogs bool) error {
	s.logger.Info().Msg("=== Uninstall TrafficGuard ===")
	s.logger.Info().Msg("TrafficGuard does not modify Linux routing tables (ip rule/ip route), skipping routing rollback")

	s.stopAndDisableServices()
	s.cleanupIPTablesRuntime()
	if err := s.cleanupUFWBeforeRules(); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cleanup UFW before.rules markers")
	}
	s.cleanupIPSet()
	s.removeArtifacts(removeLogs)

	if err := s.reloadSystemdDaemon(); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to reload systemd daemon")
	}

	if err := s.reloadRsyslog(); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to reload rsyslog")
	}

	if err := s.persistFirewallState(); err != nil {
		return fmt.Errorf("failed to persist firewall state: %w", err)
	}

	s.logger.Info().Msg("TrafficGuard uninstall completed")
	return nil
}

func (s *UninstallerService) stopAndDisableServices() {
	if !s.cmdSvc.CommandExists("systemctl") {
		s.logger.Warn().Msg("systemctl not found, skipping service stop/disable")
		return
	}

	services := []string{
		"antiscan-aggregate.timer",
		"antiscan-aggregate.service",
		"antiscan-move-rules.service",
		"antiscan-ipset-restore.service",
	}

	for _, serviceName := range services {
		if err := s.cmdSvc.StopService(serviceName); err != nil {
			s.logger.Warn().Err(err).Str("service", serviceName).Msg("Stop failed, continuing")
		}
		if err := s.cmdSvc.DisableService(serviceName); err != nil {
			s.logger.Warn().Err(err).Str("service", serviceName).Msg("Disable failed, continuing")
		}
	}
}

func (s *UninstallerService) cleanupIPTablesRuntime() {
	s.cleanupIPTablesVersion(IPv4, "ufw-before-input", "iptables")
	s.cleanupIPTablesVersion(IPv6, "ufw6-before-input", "ip6tables")
}

func (s *UninstallerService) cleanupIPTablesVersion(version IPVersion, ufwInputChain, command string) {
	if err := s.iptablesCmd.UnlinkChainFromInput(version, chainName); err != nil {
		s.logger.Warn().Err(err).Str("version", string(version)).Msg("Failed to unlink chain from INPUT, continuing")
	}

	if err := s.cmdSvc.Run(command, "-D", ufwInputChain, "-j", chainName); err != nil {
		s.logger.Warn().Err(err).Str("version", string(version)).Msg("Failed to unlink chain from UFW input, continuing")
	}

	if !s.iptablesCmd.ChainExists(version, TableFilter, chainName) {
		return
	}

	if err := s.iptablesCmd.FlushChain(version, TableFilter, chainName); err != nil {
		s.logger.Warn().Err(err).Str("version", string(version)).Msg("Failed to flush chain, continuing")
	}

	if err := s.iptablesCmd.DeleteChain(version, TableFilter, chainName); err != nil {
		s.logger.Warn().Err(err).Str("version", string(version)).Msg("Failed to delete chain, continuing")
	}
}

func (s *UninstallerService) cleanupUFWBeforeRules() error {
	changedV4, err := s.removeManagedUFWBlock(UFWBeforeRulesPath)
	if err != nil {
		return err
	}

	changedV6, err := s.removeManagedUFWBlock(UFW6BeforeRulesPath)
	if err != nil {
		return err
	}

	if (changedV4 || changedV6) && s.cmdSvc.CommandExists("ufw") {
		if err := s.cmdSvc.Run("ufw", "reload"); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to reload UFW after cleanup")
		}
	}

	return nil
}

func (s *UninstallerService) removeManagedUFWBlock(path string) (bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to read %s: %w", path, err)
	}

	updated := string(content)
	original := updated
	blocksRemoved := 0

	for {
		start := strings.Index(updated, ufwManagedBlockStart)
		if start == -1 {
			break
		}

		endRel := strings.Index(updated[start:], ufwManagedBlockEnd)
		if endRel == -1 {
			s.logger.Warn().Str("path", path).Msg("Managed block start found but no end marker, skipping")
			break
		}

		end := start + endRel + len(ufwManagedBlockEnd)

		// Skip trailing newlines
		for end < len(updated) && (updated[end] == '\n' || updated[end] == '\r') {
			end++
		}

		// Remove one leading newline if exists
		if start > 0 && updated[start-1] == '\n' {
			start--
			if start > 0 && updated[start-1] == '\r' {
				start--
			}
		} else if start > 0 && updated[start-1] == '\r' {
			start--
		}

		updated = updated[:start] + updated[end:]
		blocksRemoved++
	}

	if updated == original {
		return false, nil
	}

	tmpPath := path + ".new"
	if err := os.WriteFile(tmpPath, []byte(updated), 0640); err != nil {
		return false, fmt.Errorf("failed to write %s: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return false, fmt.Errorf("failed to replace %s: %w", path, err)
	}

	s.logger.Info().Str("path", path).Int("blocks", blocksRemoved).Msg("Removed TrafficGuard managed UFW blocks")
	return true, nil
}

func (s *UninstallerService) cleanupIPSet() {
	for _, setName := range []string{ipsetV4Name, ipsetV6Name} {
		if !s.ipsetCmd.Exists(setName) {
			continue
		}

		if err := s.ipsetCmd.Flush(setName); err != nil {
			s.logger.Warn().Err(err).Str("set", setName).Msg("Failed to flush ipset, continuing")
		}
		if err := s.ipsetCmd.Destroy(setName); err != nil {
			s.logger.Warn().Err(err).Str("set", setName).Msg("Failed to destroy ipset, continuing")
		}
	}

	if err := removeFileIfExists(IpsetConfigPath); err != nil {
		s.logger.Warn().Err(err).Str("path", IpsetConfigPath).Msg("Failed to remove ipset config")
	}
}

func (s *UninstallerService) removeArtifacts(removeLogs bool) {
	paths := []string{
		"/usr/local/bin/traffic-guard",
		IpsetRestoreServicePath,
		MoveRulesServicePath,
		AggregateLogsServicePath,
		AggregateLogsTimerPath,
		AggregateLogsScriptPath,
		RsyslogConfigPath,
		LogrotateConfigPath,
	}

	for _, path := range paths {
		if err := removeFileIfExists(path); err != nil {
			s.logger.Warn().Err(err).Str("path", path).Msg("Failed to remove file, continuing")
		}
	}

	if !removeLogs {
		return
	}

	logFiles, err := filepath.Glob("/var/log/iptables-scanners-*")
	if err != nil {
		s.logger.Warn().Err(err).Msg("Failed to enumerate log files")
		return
	}

	for _, logFile := range logFiles {
		if err := removeFileIfExists(logFile); err != nil {
			s.logger.Warn().Err(err).Str("path", logFile).Msg("Failed to remove log file")
		}
	}
}

func (s *UninstallerService) reloadSystemdDaemon() error {
	if !s.cmdSvc.CommandExists("systemctl") {
		return nil
	}

	return s.cmdSvc.DaemonReload()
}

func (s *UninstallerService) reloadRsyslog() error {
	if !s.cmdSvc.CommandExists("systemctl") {
		return nil
	}

	// Check if rsyslog service exists and is active
	if err := s.cmdSvc.Run("systemctl", "is-active", "rsyslog"); err != nil {
		s.logger.Debug().Msg("rsyslog is not active, skipping reload")
		return nil
	}

	return s.cmdSvc.RestartService("rsyslog")
}

func (s *UninstallerService) persistFirewallState() error {
	if s.cmdSvc.CommandExists("ufw") {
		s.logger.Debug().Msg("UFW detected, skipping manual iptables persistence")
		return nil
	}

	s.logger.Info().Msg("Persisting firewall state to /etc/iptables/")

	if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
		return err
	}

	if err := s.iptablesCmd.Save(IPv4, IptablesRulesV4Path); err != nil {
		return err
	}

	if err := s.iptablesCmd.Save(IPv6, IptablesRulesV6Path); err != nil {
		return err
	}

	if s.cmdSvc.CommandExists("netfilter-persistent") {
		if err := s.cmdSvc.Run("netfilter-persistent", "save"); err != nil {
			s.logger.Warn().Err(err).Msg("netfilter-persistent save failed")
		}
	}

	return nil
}

func removeFileIfExists(path string) error {
	err := os.Remove(path)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}
