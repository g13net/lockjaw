const std = @import("std");

pub const Transport = struct {
    ptr: *anyopaque,
    send_fn: *const fn (ptr: *anyopaque, path: []const u8, data: []const u8) anyerror!void,
    receive_fn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]u8,

    pub fn send(self: Transport, path: []const u8, data: []const u8) anyerror!void {
        return self.send_fn(self.ptr, path, data);
    }

    pub fn receive(self: Transport, allocator: std.mem.Allocator) anyerror![]u8 {
        return self.receive_fn(self.ptr, allocator);
    }
};
