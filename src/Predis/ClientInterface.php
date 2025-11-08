<?php

declare(strict_types=1);

namespace Predis;

if (!interface_exists(ClientInterface::class)) {
    /**
     * Minimal stub of Predis\ClientInterface to allow optional Redis integration
     * without requiring the predis/predis package at install time.
     * When predis is installed, this stub is ignored.
     */
    interface ClientInterface
    {
        /** @return string|null */
        public function get(string $key);

        /** @return mixed */
        public function set(string $key, string $value, mixed ...$args);

        /**
         * @param array<int, string> $keys
         * @return mixed
         */
        public function del(array $keys);

        /**
         * @param array<string, mixed> $options
         * @return array{0:string,1:array<int,string>}
         */
        public function scan(string $cursor, array $options = []);

        /**
         * @param array<int, string> $keys
         * @return array<int, string|null>
         */
        public function mget(array $keys);

        /** @return int|bool */
        public function exists(string $key);

        /** @return mixed */
        public function eval(string $script, int $numkeys, string ...$keysAndArgs);

        /** @return int */
        public function ttl(string $key);
    }
}
