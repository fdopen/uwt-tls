
open Lwt
open Ex_common

let http_client ?ca ?fp host port =
  let port          = int_of_string port in
  let s =  match ca, fp with
  | None, Some fp  -> `Hex_key_fingerprints (`SHA256, [(host, fp)])
  | None, _        -> `Ca_dir ca_cert_dir
  | Some "NONE", _ -> `No_authentication_I'M_STUPID
  | Some f, _      -> `Ca_file f
  in
  X509_uwt.authenticator s >>= fun authenticator ->
  Tls_uwt.connect_ext
    ~trace:eprint_sexp
    (Tls.Config.client ~authenticator ())
    (host, port) >>=  fun (ic, oc) ->
  let req = String.concat "\r\n" [
      "GET / HTTP/1.1" ; "Host: " ^ host ; "Connection: close" ; "" ; ""
    ]
  in
  let open Uwt_io in
  write oc req >>= fun () ->
  read ic >>= fun s ->
  print s >>= fun () ->
  printf "++ done.\n%!"

let () =
  try
    match Sys.argv with
    | [| _ ; host ; port ; "FP" ; fp |] -> Uwt.Main.run (http_client host port ~fp)
    | [| _ ; host ; port ; trust |] -> Uwt.Main.run (http_client host port ~ca:trust)
    | [| _ ; host ; port |]         -> Uwt.Main.run (http_client host port)
    | [| _ ; host |]                -> Uwt.Main.run (http_client host "443")
    | args                          -> Printf.eprintf "%s <host> <port>\n%!" args.(0)
  with
  | Tls_uwt.Tls_alert alert as exn ->
      print_alert "remote end" alert ; raise exn
  | Tls_uwt.Tls_failure fail as exn ->
      print_fail "our end" fail ; raise exn

