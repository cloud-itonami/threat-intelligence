#!/usr/bin/env nbb
;; Check catalog.edn against the registry's own vocabulary, and optionally
;; against the live feeds.
;;
;;     nbb scripts/verify-catalog.cljs            structure only, no network
;;     nbb scripts/verify-catalog.cljs --live     also fetch every URL
;;
;; Exit codes are three-valued on purpose:
;;
;;   0  checked, nothing wrong
;;   1  checked, findings printed
;;   2  REFUSED — could not check. Never conflated with 0.
;;
;; The last one is the point. A verifier that cannot read its input, or cannot
;; recover the vocabulary it is meant to check against, must not return the
;; same value as a verifier that looked and found nothing.
;;
;; The allowed indicator types and TLP classes are parsed out of
;; kotoba/src/types.ts rather than written down here. A second hand-maintained
;; copy of that union would agree with the code exactly until someone edited
;; one of them.

(ns verify-catalog
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            ["fs" :as fs]
            ["path" :as path]
            ["process" :as process]))

;; nbb leaves the script path in argv, so a bare `(remove #"--" argv)` makes
;; "scripts/verify-catalog.cljs" the repo root and every path resolves under it.
(def argv
  (->> (js->clj (.-argv process))
       (drop 2)
       (remove #(str/ends-with? % "verify-catalog.cljs"))
       vec))
(def live? (some #(= "--live" %) argv))
(def positional (remove #(str/starts-with? % "--") argv))

(def repo-root (or (first positional) (.cwd process)))

(defn- slurp* [p]
  (try (fs/readFileSync p "utf8") (catch :default _ nil)))

(defn refuse! [msg]
  (println (str "REFUSED\t" msg))
  (println "Refusing to report a pass: the check did not run.")
  (.exit process 2))

;; ── vocabulary, read from the implementation ────────────────────────────────

(defn- union-members
  "Every string literal in `export type <nm> = …;`, or nil if the union is absent."
  [src nm]
  (when src
    (when-let [m (re-find (re-pattern (str "export type " nm "\\s*=([^;]*);")) src)]
      (let [members (map second (re-seq #"\"([^\"]+)\"" (second m)))]
        (when (seq members) (into #{} members))))))

(def types-path (path/join repo-root "kotoba" "src" "types.ts"))
(def types-src (slurp* types-path))

(when-not types-src
  (refuse! (str "cannot read " types-path
                " — the indicator-type and TLP vocabulary is defined there, "
                "and this check has no meaning without it")))

(def indicator-types (union-members types-src "IndicatorType"))
(def tlp-classes (union-members types-src "Tlp"))

(when-not (and indicator-types tlp-classes)
  (refuse! (str "could not parse the IndicatorType and/or Tlp union out of "
                types-path " — refusing to fall back to a hardcoded copy")))

(def formats #{:json :jsonl :csv :text})
(def required-keys
  [:source/id :source/name :source/operator :source/homepage :source/url
   :source/format :source/indicator-types :source/tlp :source/authentication
   :source/note])

;; ── input ───────────────────────────────────────────────────────────────────

(def catalog-path (path/join repo-root "catalog.edn"))
(def catalog-src (slurp* catalog-path))

(when-not catalog-src (refuse! (str "cannot read " catalog-path)))

(def catalog
  (try (edn/read-string catalog-src)
       (catch :default e (refuse! (str catalog-path " is not readable EDN: " (.-message e))))))

(when-not (vector? catalog) (refuse! (str catalog-path " must be a vector of maps")))
(when (empty? catalog) (refuse! (str catalog-path " is empty — nothing to check")))
(when-not (every? map? catalog) (refuse! (str catalog-path " contains a non-map entry")))

;; ── structural findings ─────────────────────────────────────────────────────

(defn- https? [u] (and (string? u) (str/starts-with? u "https://")))

(def structural
  (concat
   ;; duplicate ids would silently merge two feeds under one `source` string
   (for [[id n] (frequencies (map :source/id catalog)) :when (> n 1)]
     [:duplicate-id (str id " appears " n " times")])
   (mapcat
    (fn [e]
      (let [id (or (:source/id e) "<no :source/id>")]
        (concat
         (for [k required-keys :when (nil? (get e k))]
           [:missing-key (str id " has no " k)])
         (when-let [i (:source/id e)]
           (when-not (re-matches #"[a-z0-9]+(-[a-z0-9]+)*" (str i))
             [[:id-shape (str i " is not a lowercase dash-separated id")]]))
         (for [k [:source/url :source/homepage]
               :when (and (some? (get e k)) (not (https? (get e k))))]
           [:url-shape (str id " " k " is not https://: " (pr-str (get e k)))])
         (when-let [f (:source/format e)]
           (when-not (formats f)
             [[:format (str id " format " (pr-str f) " is not one of " (pr-str (sort formats)))]]))
         (when-let [t (:source/tlp e)]
           (when-not (tlp-classes (name t))
             [[:tlp (str id " tlp " (pr-str t) " is not in the Tlp union: "
                        (pr-str (sort tlp-classes)))]]))
         (let [ts (:source/indicator-types e)]
           (cond
             (nil? ts) nil
             (or (not (vector? ts)) (empty? ts))
             [[:indicator-type (str id " indicator-types must be a non-empty vector")]]
             :else
             (for [t ts :when (not (indicator-types (name t)))]
               [:indicator-type (str id " indicator type " (pr-str t)
                                     " is not in the IndicatorType union")]))))))
    catalog)))

;; ── live findings ───────────────────────────────────────────────────────────

(defn- payload-lines
  "Non-blank, non-comment lines. A feed that serves only its own header is
   reachable but carries nothing, which is not the same as working."
  [body]
  (->> (str/split-lines (or body ""))
       (map str/trim)
       (remove str/blank?)
       (remove #(str/starts-with? % "#"))
       count))

(defn- probe [url want-body?]
  (-> (js/fetch url #js {:redirect "follow"
                         :headers #js {"User-Agent" "threat-intelligence-catalog-verify/1.0"}
                         :signal (js/AbortSignal.timeout 45000)})
      (.then (fn [r]
               (if (and want-body? (.-ok r))
                 (.then (.text r) (fn [t] {:status (.-status r) :body t}))
                 {:status (.-status r) :body nil})))
      (.catch (fn [e] {:status 0 :error (.-message e)}))))

(defn- live-findings []
  (-> (js/Promise.all
       (clj->js
        (for [e catalog]
          (-> (js/Promise.all #js [(probe (:source/url e) true)
                                   (probe (:source/homepage e) false)])
              (.then (fn [[feed home]]
                       (let [feed (js->clj feed :keywordize-keys true)
                             home (js->clj home :keywordize-keys true)
                             id (:source/id e)]
                         (clj->js
                          (concat
                           (when-not (<= 200 (:status feed) 299)
                             [[:url-dead (str id " feed " (:source/url e)
                                              " returned " (:status feed)
                                              (when (:error feed) (str " (" (:error feed) ")")))]])
                           (when-not (<= 200 (:status home) 299)
                             [[:homepage-dead (str id " homepage " (:source/homepage e)
                                                   " returned " (:status home)
                                                   (when (:error home) (str " (" (:error home) ")")))]])
                           (when (and (<= 200 (:status feed) 299)
                                      (zero? (payload-lines (:body feed))))
                             [[:empty-feed (str id " feed returned 200 but carries no "
                                                "non-comment lines")]]))))))))))
      (.then (fn [rs] (mapv (fn [p] [(keyword (first p)) (second p)])
                            (apply concat (js->clj rs)))))))

;; ── report ──────────────────────────────────────────────────────────────────

(defn report! [findings]
  ;; Evidence floor: say how much was actually looked at, so an empty finding
  ;; list cannot be read as clean when nothing was scanned.
  (println (str "SCANNED\t" (count catalog) " sources"
                (when live? (str ", " (* 2 (count catalog)) " URLs fetched"))))
  (println (str "VOCABULARY\t" (count indicator-types) " indicator types, "
                (count tlp-classes) " TLP classes, from kotoba/src/types.ts"))
  (if (seq findings)
    (do (doseq [[kind msg] findings] (println (str "[" (name kind) "] " msg)))
        (println (str "FINDINGS\t" (count findings)))
        (.exit process 1))
    (do (println (if live?
                   "OK — every source is well-formed and every URL served a payload"
                   "OK — every source is well-formed (structure only; pass --live to fetch)"))
        (.exit process 0))))

(if live?
  (-> (live-findings) (.then (fn [lf] (report! (concat structural lf)))))
  (report! structural))
