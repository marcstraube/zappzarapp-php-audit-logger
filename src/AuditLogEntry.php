<?php

declare(strict_types=1);

namespace Zappzarapp\AuditLogger;

use InvalidArgumentException;

/**
 * Immutable DTO representing an audit log entry to be written
 */
final readonly class AuditLogEntry
{
    private const int MAX_ACTION_LENGTH      = 255;

    private const int MAX_ENTITY_TYPE_LENGTH  = 100;

    private const int MAX_ENTITY_ID_LENGTH    = 255;

    private const int MAX_IP_ADDRESS_LENGTH   = 45;

    private const int MAX_USER_AGENT_LENGTH   = 500;

    /**
     * @param string $action Action performed (e.g., 'user.view', 'user.update')
     * @param string $entityType Entity type (e.g., 'user', 'order')
     * @param string|int $entityId Entity ID (primary key)
     * @param int|null $userId User who performed the action (null for system actions)
     * @param string $ipAddress Client IP address
     * @param string $userAgent Client user agent
     * @param array<string, mixed> $data Additional context data (will be encrypted)
     *
     * @throws InvalidArgumentException
     */
    public function __construct(
        public string $action,
        public string $entityType,
        public string|int $entityId,
        public ?int $userId = null,
        public string $ipAddress = 'unknown',
        public string $userAgent = 'unknown',
        public array $data = [],
    ) {
        $this->validateNotEmpty($this->action, 'Action');
        $this->validateMaxLength($this->action, 'Action', self::MAX_ACTION_LENGTH);
        $this->validateNotEmpty($this->entityType, 'Entity type');
        $this->validateMaxLength($this->entityType, 'Entity type', self::MAX_ENTITY_TYPE_LENGTH);
        $this->validateNotEmpty((string) $this->entityId, 'Entity ID');
        $this->validateMaxLength((string) $this->entityId, 'Entity ID', self::MAX_ENTITY_ID_LENGTH);
        $this->validateMaxLength($this->ipAddress, 'IP address', self::MAX_IP_ADDRESS_LENGTH);
        $this->validateMaxLength($this->userAgent, 'User agent', self::MAX_USER_AGENT_LENGTH);
    }

    /** @throws InvalidArgumentException */
    private function validateNotEmpty(string $value, string $field): void
    {
        if ($value === '') {
            throw new InvalidArgumentException($field . ' must not be empty');
        }
    }

    /** @throws InvalidArgumentException */
    private function validateMaxLength(string $value, string $field, int $max): void
    {
        if (strlen($value) > $max) {
            throw new InvalidArgumentException($field . ' must not exceed ' . $max . ' bytes');
        }
    }
}
