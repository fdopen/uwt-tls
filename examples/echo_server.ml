open Lwt
open Ex_common

let wait () =
  let signals = [ Sys.sigint; Sys.sigterm ] in
  let sleeper,waker = Lwt.task () in
  let wake_once = lazy (Lwt.wakeup waker () ) in
  let cb _sig _i  = Lazy.force wake_once  in
  let l = List.map ( fun s -> Uwt.Signal.start_exn s ~cb ) signals in
  let close_all () = List.iter Uwt.Signal.close_noerr l; Lwt.return_unit in
  Lwt.finalize ( fun () -> sleeper) ( fun () -> close_all () )

let serve_ssl port callback =
  let tag = "server" in
  X509_uwt.private_of_pems
    ~cert:server_cert
    ~priv_key:server_key
  >>= fun cert ->
  X509_uwt.authenticator `No_authentication_I'M_STUPID >>= fun authenticator ->
  let config = Tls.Config.server ~certificates:(`Single cert) ~authenticator () in
  let server_s = Uwt.Tcp.init () in
  let rec echo_server () =
    Lwt.finalize ( fun () ->
        let addr = Uwt.Misc.ip4_addr_exn "127.0.0.1" port in
        Uwt.Tcp.bind_exn server_s ~addr ();
        let () = Uwt.Tcp.listen_exn server_s ~max:10 ~cb:on_listen in
        wait ()
      ) ( fun () -> Uwt.Tcp.close_noerr server_s; Lwt.return_unit )
  and on_listen _server res =
    if Uwt.Int_result.is_error res then
      let () = prerr_endline "fatal error" in
      exit 1
    else
      Lwt.catch ( fun () ->
          Tls_uwt.accept_ext ~trace:eprint_sexp config server_s >>= fun (channels, addr) ->
          yap ~tag "-> connect"
          >>= fun () ->
          callback channels addr >>= fun () -> yap ~tag "<- handler done"
        )
        (function
        | Tls_uwt.Tls_alert a ->
          yap ~tag @@ "handler: " ^ Tls.Packet.alert_type_to_string a
        | exn ->
          yap ~tag "handler: exception" >>= fun () -> fail exn )
      |> ignore
  in
  echo_server ()

let echo_server port =
  serve_ssl port @@ fun (ic, oc) _addr ->
  lines ic |> Lwt_stream.iter_s @@ fun line ->
  yap ~tag:"handler" ("+ " ^ line) >>= fun () -> Uwt_io.write_line oc line

let () =
  let port =
    try int_of_string Sys.argv.(1) with _ -> 4433
  in
  Printf.printf
    "you can also connect with 'openssl s_client -connect 127.0.0.1:%d'\n%!"
    port;
  echo_server port |> Uwt.Main.run
