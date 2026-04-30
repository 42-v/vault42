package redis

// Nil is returned when a Redis key does not exist.
// Check with errors.Is(err, redis.Nil).
const Nil = nilError("redis: nil")

type nilError string

func (e nilError) Error() string { return string(e) }

// RedisError represents a server-side Redis error response.
type RedisError struct {
	Msg string
}

func (e *RedisError) Error() string { return "redis: " + e.Msg }
