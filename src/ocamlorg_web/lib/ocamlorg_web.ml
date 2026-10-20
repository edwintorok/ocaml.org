module Handler = Handler
(** Entrypoint to OCaml.org' web library. *)

module Graphql = Graphql

(* Exposed for tests: the Block B doc-HTML sanitiser / reference extractor
   (issue #3775). *)
module Mcp_doc_html = Mcp_doc_html

(* Exposed for tests: the MCP tool assembly (issue #3775), so the red-team
   transport test can drive the production sanitisation projections
   ([sanitized_doc_fields] / [sanitized_overview_fields]) end to end through the
   JSON-RPC transport. *)
module Mcp_tools = Mcp_tools

module Heap_size_watcher = struct
  let src = Logs.Src.create "heap_size_watcher"
  module Log = (val Logs.src_log src)

  let desired_heap_size_words =
    (Config.desired_heap_size_mib lsl 20) / (Sys.word_size / 8)

  let additional_slices = ref 0

  let reduce_heap_size = Lwt_condition.create ()

  let active_requests = Atomic.make 0

  let rec reduce_heap_size_worker () =
    let open Lwt.Syntax in
    let* () = Lwt_condition.wait reduce_heap_size in
    (* ensure more accurate statistics *)
    Gc.minor ();
    let sampled_stats = Gc.(quick_stat ()) in
    let delta_words = sampled_stats.heap_words - desired_heap_size_words in
    Log.debug (fun m -> m "reduce_heap_size_loop, delta_words = %d" delta_words);
    if delta_words > 0 then begin
      incr additional_slices;
      let active = Atomic.get active_requests in
      let slice_words = delta_words / (1 + active) in
      Log.info (fun m -> m "Heap size exceeded by %d words (additional slices: %d), active requests = %d, major_slice = %d" delta_words !additional_slices
        active slice_words
      );
      let (_ : int) = Gc.major_slice slice_words in
      ()
    end;
    reduce_heap_size_worker ()

  let init () =
    Lwt.async reduce_heap_size_worker


  let on_req_begin () =
    Atomic.incr active_requests

  let on_req_complete () =
    Atomic.decr active_requests;
    let sampled_stats = Gc.(quick_stat ()) in
    let live_words = sampled_stats.live_words
    and space_overhead = Gc.(get ()).space_overhead in
    let estimated_heap_size_words = live_words / 100 * (100 + space_overhead) in
    Log.debug (fun m -> m
      "active requests remaining %d, heap_size_words: estimated %d, desired %d, headroom %d, actual %d, headroom' %d"
        (Atomic.get active_requests)
        estimated_heap_size_words desired_heap_size_words
        (desired_heap_size_words - estimated_heap_size_words)
        sampled_stats.heap_words
        (desired_heap_size_words - sampled_stats.heap_words)
      );
    if estimated_heap_size_words > desired_heap_size_words ||
      sampled_stats.heap_words > desired_heap_size_words then begin
      Log.debug (fun m -> m "running major_slice 0");
      incr additional_slices;
      (* collect between requests *)
      let (_ : int) = Gc.major_slice 0 in
      if sampled_stats.heap_words > desired_heap_size_words then begin
          Log.debug (fun m -> m "signaling to reduce heap size");
          Lwt_condition.signal reduce_heap_size ()
      end
    end
end

let on_request_wrap on_begin on_completed next_handler req =
  on_begin ();
  let promise = next_handler req in
  Lwt.on_termination promise on_completed;
  promise

(* Set up basic logging for logs that would happen before Dream is set up. *)
let () =
  Logs.set_reporter (Logs.format_reporter ());
  Logs.set_level (Some Info)

let run () =
  Mirage_crypto_rng_unix.use_default ();
  let state = Ocamlorg_package.init () in
  Heap_size_watcher.init ();
  try
    Dream.run ~interface:"0.0.0.0" ~port:Config.http_port
    @@ on_request_wrap Heap_size_watcher.on_req_begin Heap_size_watcher.on_req_complete
    @@ Dream.logger @@ Middleware.no_trailing_slash
    @@ Middleware.language_manual_version @@ Middleware.head
    @@ Router.router state
  with
  | Unix.Unix_error (err, fn, _) ->
      Format.eprintf "%S failed: %s@." fn (Unix.error_message err);
      (match err with
      | EADDRINUSE ->
          Format.eprintf
            "Hint: Try changing the value of the environment variable \
             OCAMLORG_HTTP_PORT@."
      | _ -> ());
      exit 2
  | exn ->
      Format.eprintf "%s" (Printexc.to_string exn);
      exit 2
