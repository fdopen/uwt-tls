open Ex_common
open Lwt

let echo_client ?ca host port =
  let open Uwt_io in

  let port          = int_of_string port in
  X509_uwt.authenticator (match ca with
     | None        -> `Ca_dir ca_cert_dir
     | Some "NONE" -> `No_authentication_I'M_STUPID
     | Some f      -> `Ca_file f) >>= fun authenticator ->
  X509_uwt.private_of_pems
    ~cert:server_cert
    ~priv_key:server_key
  >>= fun certificate ->
  Tls_uwt.connect_ext
    ~trace:eprint_sexp
    Tls.Config.(client ~authenticator
                  ~certificates:(`Single certificate)
                  ~ciphers:Ciphers.supported ())
    (host, port)
  >>= fun (ic,oc) ->
  Lwt.join [
    lines ic    |> Lwt_stream.iter_s (printf "+ %s\n%!") ;
    lines Uwt_io.stdin |> Lwt_stream.iter_s (write_line oc)
  ]

let () =
 try (
    match Sys.argv with
    | [| _ ; host ; port ; trust |] -> Uwt.Main.run (echo_client host port ~ca:trust)
    | [| _ ; host ; port |]         -> Uwt.Main.run (echo_client host port)
    | [| _ ; host |]                -> Uwt.Main.run (echo_client host "443")
    | args                          -> Printf.eprintf "%s <host> <port>\n%!" args.(0) ) with
  | Tls_uwt.Tls_alert alert as exn ->
      print_alert "remote end" alert ; raise exn
  | Tls_uwt.Tls_failure alert as exn ->
      print_fail "our end" alert ; raise exn
