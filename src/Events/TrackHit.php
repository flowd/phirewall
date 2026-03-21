<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Events;

use Psr\Http\Message\ServerRequestInterface;

final readonly class TrackHit
{
    /** True when limit is set and count >= limit. Computed from limit and count. */
    public bool $thresholdReached;

    /**
     * @param string $rule Rule name that triggered the event
     * @param string $key Discriminator key for the tracked entity
     * @param int $period Time window in seconds
     * @param int $count Current counter value within the period
     * @param ServerRequestInterface $serverRequest The request that triggered tracking
     * @param int|null $limit Configured threshold (null if no limit was set)
     */
    public function __construct(
        public string $rule,
        public string $key,
        public int $period,
        public int $count,
        public ServerRequestInterface $serverRequest,
        public ?int $limit = null,
    ) {
        $this->thresholdReached = $this->limit !== null && $this->count >= $this->limit;
    }
}
