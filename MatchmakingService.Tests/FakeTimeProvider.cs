namespace MatchmakingService.Tests;

public sealed class FakeTimeProvider(DateTimeOffset? initialTime = null) : TimeProvider
{
    private readonly object _gate = new();
    private readonly List<FakeTimer> _timers = [];
    private DateTimeOffset _now = initialTime ?? DateTimeOffset.Parse("2025-01-01T00:00:00Z");

    public override DateTimeOffset GetUtcNow()
    {
        lock (_gate) return _now;
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        lock (_gate)
        {
            var timer = new FakeTimer(this, callback, state, dueTime, period);
            _timers.Add(timer);
            return timer;
        }
    }

    public void Advance(TimeSpan amount)
    {
        if (amount < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(amount));
        DateTimeOffset target;
        lock (_gate)
        {
            target = _now + amount;
            while (true)
            {
                var next = _timers.Where(timer => !timer.Disposed && timer.DueAt is not null && timer.DueAt <= target)
                    .OrderBy(timer => timer.DueAt).FirstOrDefault();
                if (next is null) break;
                _now = next.DueAt!.Value;
                next.Fire();
            }
            _now = target;
        }
    }

    private void Remove(FakeTimer timer)
    {
        lock (_gate) _timers.Remove(timer);
    }

    private sealed class FakeTimer(FakeTimeProvider owner, TimerCallback callback, object? state,
        TimeSpan dueTime, TimeSpan period) : ITimer
    {
        public DateTimeOffset? DueAt { get; private set; } = dueTime == Timeout.InfiniteTimeSpan ? null : owner.GetUtcNow() + dueTime;
        private TimeSpan _period = period;
        public bool Disposed { get; private set; }

        public bool Change(TimeSpan newDueTime, TimeSpan newPeriod)
        {
            if (Disposed) return false;
            DueAt = newDueTime == Timeout.InfiniteTimeSpan ? null : owner.GetUtcNow() + newDueTime;
            _period = newPeriod;
            return true;
        }

        public void Fire()
        {
            if (_period == Timeout.InfiniteTimeSpan || _period == TimeSpan.Zero) DueAt = null;
            else DueAt = DueAt!.Value + _period;
            callback(state);
        }

        public void Dispose()
        {
            if (Disposed) return;
            Disposed = true;
            owner.Remove(this);
        }

        public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
    }
}
