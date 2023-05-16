# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "logstash/json"
require "logstash/util/safe_uri"
java_import "java.util.concurrent.ConcurrentHashMap"
require "opensearch"
require "opensearch/transport/transport/http/manticore"
require_relative "opensearch/patches/_opensearch_transport_http_manticore"
require_relative "opensearch/patches/_opensearch_transport_connections_selector"


class LogStash::Filters::OpenSearch < LogStash::Filters::Base
  config_name "opensearch"

  DEFAULT_HOST = ::LogStash::Util::SafeURI.new("//localhost:9200")

  # List of opensearch hosts to use for querying.
  config :hosts, :validate => :array, :default => [ DEFAULT_HOST ]

  # Comma-delimited list of index names to search; use `_all` or empty string to perform the operation on all indices.
  # Field substitution (e.g. `index-name-%{date_field}`) is available
  config :index, :validate => :string, :default => ""

  # OpenSearch query string. Read the OpenSearch query string documentation.
  # for more info at: https://www.elastic.co/guide/en/opensearch/reference/master/query-dsl-query-string-query.html#query-string-syntax
  config :query, :validate => :string

  # File path to opensearch query in DSL format. Read the OpenSearch query documentation
  # for more info at: https://www.elastic.co/guide/en/opensearch/reference/current/query-dsl.html
  config :query_template, :validate => :string

  # Comma-delimited list of `<field>:<direction>` pairs that define the sort order
  config :sort, :validate => :string, :default => "@timestamp:desc"

  # Array of fields to copy from old event (found via opensearch) into new event
  config :fields, :validate => :array, :default => {}

  # Hash of docinfo fields to copy from old event (found via opensearch) into new event
  config :docinfo_fields, :validate => :hash, :default => {}

  # Hash of aggregation names to copy from opensearch response into Logstash event fields
  config :aggregation_fields, :validate => :hash, :default => {}

  # Basic Auth - username
  config :user, :validate => :string

  # Basic Auth - password
  config :password, :validate => :password

  # Cloud ID, from the Elastic Cloud web console. If set `hosts` should not be used.
  #
  # For more info, check out the https://www.elastic.co/guide/en/logstash/current/connecting-to-cloud.html#_cloud_id[Logstash-to-Cloud documentation]
  config :cloud_id, :validate => :string

  # Cloud authentication string ("<username>:<password>" format) is an alternative for the `user`/`password` configuration.
  #
  # For more info, check out the https://www.elastic.co/guide/en/logstash/current/connecting-to-cloud.html#_cloud_auth[Logstash-to-Cloud documentation]
  config :cloud_auth, :validate => :password

  # Authenticate using OpenSearch API key.
  # format is id:api_key (as returned by https://www.elastic.co/guide/en/opensearch/reference/current/security-api-create-api-key.html[Create API key])
  config :api_key, :validate => :password

  # SSL
  config :ssl, :validate => :boolean, :default => false

  # SSL Certificate Authority file
  config :ca_file, :validate => :path

  # Whether results should be sorted or not
  config :enable_sort, :validate => :boolean, :default => true

  # How many results to return
  config :result_size, :validate => :number, :default => 1

  # Tags the event on failure to look up geo information. This can be used in later analysis.
  config :tag_on_failure, :validate => :array, :default => ["_opensearch_lookup_failure"]

  attr_reader :clients_pool

  def register
    @clients_pool = java.util.concurrent.ConcurrentHashMap.new

    #Load query if it exists
    if @query_template
      if File.zero?(@query_template)
        raise "template is empty"
      end
      file = File.open(@query_template, 'r')
      @query_dsl = file.read
    end

    validate_authentication

    @transport_options = {:headers => {}}
    @transport_options[:headers].merge!(setup_basic_auth(user, password))
    @transport_options[:headers].merge!({'user-agent' => prepare_user_agent })
    @transport_options[:request_timeout] = @request_timeout_seconds unless @request_timeout_seconds.nil?
    @transport_options[:connect_timeout] = @connect_timeout_seconds unless @connect_timeout_seconds.nil?
    @transport_options[:socket_timeout]  = @socket_timeout_seconds  unless @socket_timeout_seconds.nil?

    @hosts = setup_hosts
    @ssl_options = setup_ssl

    test_connection!
  end # def register

  def filter(event)
    matched = false
    begin
      params = {:index => event.sprintf(@index) }

      if @query_dsl
        query = LogStash::Json.load(event.sprintf(@query_dsl))
        params[:body] = query
      else
        query = event.sprintf(@query)
        params[:q] = query
        params[:size] = result_size
        params[:sort] =  @sort if @enable_sort
      end

      @logger.debug("Querying opensearch for lookup", :params => params)

      results = get_client.search(params)
      raise "OpenSearch query error: #{results["_shards"]["failures"]}" if results["_shards"].include? "failures"

      event.set("[@metadata][total_hits]", extract_total_from_hits(results['hits']))

      resultsHits = results["hits"]["hits"]
      if !resultsHits.nil? && !resultsHits.empty?
        matched = true
        @fields.each do |old_key, new_key|
          old_key_path = extract_path(old_key)
          set = resultsHits.map do |doc|
            extract_value(doc["_source"], old_key_path)
          end
          event.set(new_key, set.count > 1 ? set : set.first)
        end
        @docinfo_fields.each do |old_key, new_key|
          old_key_path = extract_path(old_key)
          set = resultsHits.map do |doc|
            extract_value(doc, old_key_path)
          end
          event.set(new_key, set.count > 1 ? set : set.first)
        end
      end

      resultsAggs = results["aggregations"]
      if !resultsAggs.nil? && !resultsAggs.empty?
        matched = true
        @aggregation_fields.each do |agg_name, ls_field|
          event.set(ls_field, resultsAggs[agg_name])
        end
      end

    rescue => e
      if @logger.trace?
        @logger.warn("Failed to query opensearch for previous event", :index => @index, :query => query, :event => event.to_hash, :error => e.message, :backtrace => e.backtrace)
      elsif @logger.debug?
        @logger.warn("Failed to query opensearch for previous event", :index => @index, :error => e.message, :backtrace => e.backtrace)
      else
        @logger.warn("Failed to query opensearch for previous event", :index => @index, :error => e.message)
      end
      @tag_on_failure.each{|tag| event.tag(tag)}
    else
      filter_matched(event) if matched
    end
  end # def filter

  private

  def new_client
    # NOTE: could pass cloud-id/cloud-auth to client but than we would need to be stricter on ES version requirement
    # and also LS parsing might differ from ES client's parsing so for consistency we do not pass cloud options ...
    OpenSearch::Client.new(
      :hosts => @hosts,
      :transport_options => @transport_options,
      :transport_class => ::OpenSearch::Transport::Transport::HTTP::Manticore,
      :ssl => @ssl_options
    )
  end

  def get_client
    @clients_pool.computeIfAbsent(Thread.current, lambda { |x| new_client })
  end

  # get an array of path elements from a path reference
  def extract_path(path_reference)
    return [path_reference] unless path_reference.start_with?('[') && path_reference.end_with?(']')

    path_reference[1...-1].split('][')
  end

  # given a Hash and an array of path fragments, returns the value at the path
  # @param source [Hash{String=>Object}]
  # @param path [Array{String}]
  # @return [Object]
  def extract_value(source, path)
    path.reduce(source) do |memo, old_key_fragment|
      break unless memo.include?(old_key_fragment)
      memo[old_key_fragment]
    end
  end

  # Given a "hits" object from an OpenSearch response, return the total number of hits in
  # the result set.
  # @param hits [Hash{String=>Object}]
  # @return [Integer]
  def extract_total_from_hits(hits)
    total = hits['total']

    # OpenSearch 7.x produces an object containing `value` and `relation` in order
    # to enable unambiguous reporting when the total is only a lower bound; if we get
    # an object back, return its `value`.
    return total['value'] if total.kind_of?(Hash)

    total
  end

  def hosts_default?(hosts)
    # NOTE: would be nice if pipeline allowed us a clean way to detect a config default :
    hosts.is_a?(Array) && hosts.size == 1 && hosts.first.equal?(DEFAULT_HOST)
  end

  def validate_authentication
    authn_options = 0
    authn_options += 1 if @cloud_auth
    authn_options += 1 if (@api_key && @api_key.value)
    authn_options += 1 if (@user || (@password && @password.value))

    if authn_options > 1
      raise LogStash::ConfigurationError, 'Multiple authentication options are specified, please only use one of user/password, cloud_auth or api_key'
    end

    if @api_key && @api_key.value && @ssl != true
      raise(LogStash::ConfigurationError, "Using api_key authentication requires SSL/TLS secured communication using the `ssl => true` option")
    end
  end

  def setup_hosts
    @hosts = Array(@hosts).map { |host| host.to_s } # potential SafeURI#to_s
    if @ssl
      @hosts.map do |h|
        host, port = h.split(":")
        { :host => host, :scheme => 'https', :port => port }
      end
    else
      @hosts
    end
  end

  def setup_ssl
    return { :ssl  => true, :ca_file => @ca_file } if @ssl && @ca_file
    return { :ssl  => true, :verify => false } if @ssl  # Setting verify as false if ca_file is not provided
  end

  def setup_basic_auth(user, password)
    return {} unless user && password && password.value

    token = ::Base64.strict_encode64("#{user}:#{password.value}")
    { 'Authorization' => "Basic #{token}" }
  end

  def prepare_user_agent
    os_name = java.lang.System.getProperty('os.name')
    os_version = java.lang.System.getProperty('os.version')
    os_arch = java.lang.System.getProperty('os.arch')
    jvm_vendor = java.lang.System.getProperty('java.vendor')
    jvm_version = java.lang.System.getProperty('java.version')

    plugin_version = Gem.loaded_specs["logstash-filter-opensearch-manticore"].version
    # example: logstash/7.14.1 (OS=Linux-5.4.0-84-generic-amd64; JVM=AdoptOpenJDK-11.0.11) logstash-input-opensearch/4.10.0
    "logstash/#{LOGSTASH_VERSION} (OS=#{os_name}-#{os_version}-#{os_arch}; JVM=#{jvm_vendor}-#{jvm_version}) logstash-#{@plugin_type}-#{config_name}/#{plugin_version}"
  end

  def test_connection!
    get_client.ping
  end
end #class LogStash::Filters::OpenSearch
