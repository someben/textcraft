#!/usr/bin/env ruby

require 'cgi'
require 'digest/md5'
require 'erb'
require 'io/wait'
require 'logger'
require 'net/http'
require 'net/https'
require 'securerandom'
require 'socket'
require 'timeout'
require 'uri'

require 'rubygems'
require 'json'
require 'mysql'
require 'rack/ssl'
require 'sinatra/base'
require 'sinatra/cookies'
require 'websocket-eventmachine-client'

IS_DEVELOPMENT = false
Thread.abort_on_exception = true

DEFAULT_DB_URL = "mysql://SOME_DATABASE/textcraft"
SLACK_APP_CLIENT_ID = "SOME_SLACK_CLIENT_ID"
SLACK_APP_CLIENT_SECRET = "SOME_SLACK_CLIENT_SECRET"


class String

    def to_md5
        Digest::MD5.hexdigest(self)
    end

    def to_short(len = 80 * 4) 
        self_len = self.length
        return self if self_len <= len 
        if len < 9 
            self[0...len]
        else
            ell = "..."
            pre_i = (len - ell.length) / 2 
            post_i = pre_i
            pre_i -= 1 unless (len % 2).zero?
            self[0..pre_i] + ell + self[-post_i..-1]
        end 
    end 

end


class Hash

    def values_at1(*args)
        vals = self.values_at(*args)
        return vals.first if vals.length == 1
        vals
    end

end


class Time

    ONE_SECOND = 1
    ONE_MINUTE = ONE_SECOND * 60
    ONE_HOUR = ONE_MINUTE * 60
    ONE_DAY = ONE_HOUR * 24
    ONE_WEEK = ONE_DAY * 7

end


class Console

    def self.to_io(io, level, msg)
        full_msg = "[#{Time.now}] -- #{level} -- #{msg}"
        io.puts full_msg
        io.flush
    end

    def self.verbose(msg)
        #self.to_io($stdout, " VERB", msg)
    end

    def self.debug(msg)
        self.to_io($stdout, "DEBUG", msg)
    end

    def self.info(msg)
        self.to_io($stdout, " INFO", msg)
    end

    def self.warn(msg)
        self.to_io($stderr, " WARN", msg)
    end

    def self.error(msg)
        self.to_io($stderr, "ERROR", msg)
    end

end


class Database

    def initialize(init_url = DEFAULT_DB_URL)
        @url = init_url
        uri_obj = URI(@url)
        db_scheme = uri_obj.scheme
        raise "Unrecognized database scheme" unless db_scheme == "mysql"
        db_host = uri_obj.host
        db_port = uri_obj.port

        db_param_map = uri_obj.query ? CGI.parse(uri_obj.query) : {}
        param_db_user = db_param_map.has_key?("user") ? db_param_map["user"].first : nil
        param_db_password = db_param_map.has_key?("password") ? db_param_map["password"].first : nil
        db_user = uri_obj.user || param_db_user
        db_password = uri_obj.password || param_db_password

        db_name = nil
        db_name = $1 if uri_obj.path =~ %r|^/(.+)|

        @conn = Mysql.new(db_host, db_user, db_password, db_name, db_port)
        @conn.set_server_option(Mysql::OPTION_MULTI_STATEMENTS_ON)
        @conn.reconnect = true    # to avoid the "server gone away" errors
        @insert_id = nil
    end

    def close
        @conn.close
    end

    def self.open(url = DEFAULT_DB_URL)
        db = self.new(url)
        begin
            return yield(db)
        ensure
            db.close
        end
    end

    def run_sql(sql, *args)
        Console.verbose("Running \"#{sql}\" SQL.")
        stmt = @conn.prepare(sql)
        stmt.execute(*args)
        rs_meta = stmt.result_metadata
        return nil if rs_meta.nil?
        field_names = rs_meta.fetch_fields.map { |field| field.name.to_sym }
        @insert_id = @conn.insert_id

        result = nil
        while row_vals = stmt.fetch do
            row = Hash[*field_names.zip(row_vals).flatten]
            if block_given?
                result = yield(row)
            else
                result = [] if result.nil?
                result << row
            end
        end
        result
    end

    def get_user(user_id)
        sql = <<-EOF_SQL
            SELECT `id`,
                `slack_team_id`,
                `slack_user_id`,
                `slack_user_name`,
                `slack_team_name`,
                `slack_access_tok`,
                `slack_access_scopes`
            FROM `tc_users`
            WHERE (`id` = ?);
        EOF_SQL
        run_sql(sql, user_id) do |row|
            return row
        end
        nil
    end

    def get_user_id_from_slack_ids(slack_team_id, slack_user_id)
        sql = <<-EOF_SQL
            SELECT `id` FROM `tc_users`
            WHERE (`slack_team_id` = ?) AND (`slack_user_id` = ?);
        EOF_SQL
        run_sql(sql, slack_team_id, slack_user_id) do |row|
            return row[:id]
        end
        nil
    end

    def auth_slack_user(slack_team, slack_team_id, slack_user, slack_user_id, access_tok, access_scopes)
        user_id = get_user_id_from_slack_ids(slack_team_id, slack_user_id)
        sql = <<-EOF_SQL
            INSERT INTO `tc_users` (`slack_team_name`, `slack_team_id`, `slack_user_name`, `slack_user_id`, `slack_access_tok`, `slack_access_scopes`)
            VALUES (?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE `slack_team_name` = ?, `slack_user_name` = ?, `slack_access_tok` = ?, `slack_access_scopes` = ?;
        EOF_SQL
        run_sql(sql,
            slack_team, slack_team_id, slack_user, slack_user_id, access_tok, access_scopes.join(","),
            slack_team, slack_user, access_tok, access_scopes.join(","))
    end

    def get_worlds(user_id = nil)
        world_rows = if user_id.nil?
            sql = <<-EOF_SQL
                SELECT `tc_worlds`.`id`, `tc_worlds`.`name`, `tc_worlds`.`url`, `tc_worlds`.`group_prefix`, `tc_worlds`.`desc`,
                    NULL AS `world_user_name`, NULL AS `slack_channel_id`
                FROM `tc_worlds`;
            EOF_SQL
            run_sql(sql)
        else
            sql = <<-EOF_SQL
                SELECT `tc_worlds`.`id`, `tc_worlds`.`name`, `tc_worlds`.`url`, `tc_worlds`.`group_prefix`, `tc_worlds`.`desc`,
                    `tc_world_users`.`world_user_name`, `tc_world_users`.`slack_channel_id`
                FROM `tc_worlds`
                LEFT OUTER JOIN `tc_world_users` ON
                    (`tc_worlds`.`id` = `tc_world_users`.`world_id`) AND (`tc_world_users`.`user_id` = ?);
            EOF_SQL
            run_sql(sql, user_id)
        end

        world_row_sort_fn = Proc.new { |world_row| [(URI(world_row[:url]).scheme == "textcraft") ? 1 : 0, world_row[:id]] }
        world_rows = world_rows.sort { |a, b| world_row_sort_fn.call(a) <=> world_row_sort_fn.call(b) }

        world_rows = world_rows.select { |world_row| URI(world_row[:url]).scheme == "telnet" }  # NOTE remove internal worlds, for now
        world_rows
    end

    def get_world_user_name(world_id, slack_user_name)
        sql = <<-EOF_SQL
            SELECT `world_user_name` FROM `tc_world_users`
            WHERE (`world_id` = ?);
        EOF_SQL
        current_names = Set.new
        run_sql(sql, world_id) do |row|
            current_names << row[:world_user_name]
        end
        Console.debug("World w/ #{world_id} ID has #{current_names.length} current user names.")
        return slack_user_name unless current_names.member?(slack_user_name)

        i = 1
        while i < 1_000
            maybe_name = "#{slack_user_name}#{i}"
            return maybe_name unless current_names.member?(maybe_name)
            i += 1
        end
        raise ArgumentError("Could not find unique world name from \"#{slack_user_name}\" base")
    end

    def join_world(world_id, user_id, slack_channel_id)
        user = get_user(user_id)
        world_user_name = get_world_user_name(world_id, user[:slack_user_name])
        sql = <<-EOF_SQL
            INSERT INTO `tc_world_users` (`user_id`, `world_id`, `world_user_name`, `slack_channel_id`, `status`)
            VALUES (?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE `slack_channel_id` = ?, `status` = ?;
        EOF_SQL
        run_sql(sql, user_id, world_id, world_user_name, slack_channel_id, WorldConn::IS_NEW_STATUS, slack_channel_id, WorldConn::IS_NEW_STATUS)
    end

    def update_world_connection_status(slack_channel_id, new_status)
        sql = <<-EOF_SQL
            UPDATE `tc_world_users` SET `status` = ?
            WHERE `slack_channel_id` = ?;
        EOF_SQL
        run_sql(sql, new_status, slack_channel_id)
    end

    def each_world_connection_row
        extra_where = (IS_DEVELOPMENT ? "AND `tc_users`.`slack_user_name` = 'someben'" : "")
        sql = <<-EOF_SQL
            SELECT
                `tc_world_users`.`id`,
                `tc_worlds`.`name`, `tc_worlds`.`url`, `tc_worlds`.`group_prefix`,
                `tc_world_users`.`world_user_name`, `tc_world_users`.`slack_channel_id`, `tc_world_users`.`status`,
                `tc_users`.`slack_team_name`, `tc_users`.`slack_team_id`, `tc_users`.`slack_user_name`, `tc_users`.`slack_user_id`, `tc_users`.`slack_access_tok`
            FROM `tc_world_users`
                INNER JOIN `tc_users` ON `tc_world_users`.`user_id` = `tc_users`.`id`
                INNER JOIN `tc_worlds` ON `tc_world_users`.`world_id` = `tc_worlds`.`id`
            WHERE (`tc_world_users`.`status` IN (?, ?)) #{extra_where}
            ;
        EOF_SQL
        result = nil
        run_sql(sql, WorldConn::IS_NEW_STATUS, WorldConn::IS_ACTIVE_STATUS) do |row|
            result = yield(row)
        end
        result
    end

end


class SlackApi

    MAX_RTM_MSG_TEXT_LENGTH = 4_000

    def self.format_world_msg(world_url, raw_msg)
        is_fixed_width = URI(world_url).scheme == "telnet"
        msg = raw_msg.dup

        msg.gsub!(/\r\n/, "\n")
        msg.gsub!(/\r/, "")

        msg.gsub!(/^\n+/, "")
        msg.gsub!(/\n+$/, "\n")

        msg.gsub!(/\x1B\[\S?[KJ]/, "")  # remove VT100 clearing commands (http://www.uqac.ca/flemieux/PRO100/VT100_Escape_Codes.html)

        msg.gsub!(/\xFF[\xFB-\xFE]./, "")  # remove Telnet commands w/ option codes (https://tools.ietf.org/html/rfc854)
        msg.gsub!(/\xFF[\xF0-\xFA]/, "")  # remove Telnet commands w/O option codes

        msg.gsub!(/\x1B\[1m(.*)\x1B\[0m/, "*\\1*") unless is_fixed_width    # Slack bold, http://en.wikipedia.org/wiki/ANSI_escape_code#Colors
        msg.gsub!(/\x1B\[[^m]+m/, "")  # remove ANSI escape codes

        msg.gsub!("&", "&amp;")
        msg.gsub!("<", "&lt;")
        msg.gsub!(">", "&gt;")

        msg.gsub!("`", "'") unless is_fixed_width  # single-quote substitute
        return nil if msg.strip.empty?

        msg = "```" + msg + "```" if is_fixed_width
        Console.verbose("Formatting #{raw_msg.inspect} as #{msg.inspect} for Slack.")
        msg
    end

    def self.unformat_slack_msg(raw_msg)
        msg = raw_msg.dup

        msg.gsub!(/<((#C)|(@U))\S+\|(.*?)>/, "\\4")  # Slack channel or user reference w/ pretty version
        msg.gsub!(/<((#C)|(@U))(.*?)>/, "\\4")  # Slack channel or user reference w/O pretty version, replace with the channel or user ID, for now
        msg.gsub!(/<!((channel)|(group)|(everyone))>/, "")  # Slack special commands, direct messages appropriately, just ignore for TextCraft
        msg.gsub!(/<!?.*?\|(.*?)>/, "\\1")  # other refernces w/ pretty version
        msg.gsub!(/<!?(.*?)>/, "\\1")  # other refernces w/O pretty version

        msg.gsub!("&amp;", "&")
        msg.gsub!("&lt;", "<")
        msg.gsub!("&gt;", ">")

        msg
    end

    def self.call(meth, params = {})
        url = "https://slack.com/api/" + meth
        url_params = []
        params.each_pair do |param_name, param_value|
            url_params << CGI.escape(param_name.to_s) + "=" + CGI.escape(param_value.to_s)
        end
        url += "?" + url_params.join("&") unless url_params.empty?
        url_obj = URI(url)
        Console.debug("Calling Slack w/ \"#{url.to_short}\" GET request.")

        http = Net::HTTP.new(url_obj.host, url_obj.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http_req = Net::HTTP::Get.new(url_obj.request_uri)
        http_resp = http.request(http_req)
        http_resp_obj = nil
        begin
            http_resp_obj = JSON.parse(http_resp.body)
        rescue JSON::ParserError =>ex
            Console.error("Bad Slack API call, could not parse JSON response.")
            raise ArgumentError.new("slack_api:bad_json")
        end
        unless http_resp_obj["ok"]
            Console.error("Bad Slack API call, \"#{http_resp.body}\" response.")
            raise ArgumentError.new("slack_api:" + http_resp_obj["error"])
        end

        Console.debug("Response of #{http_resp_obj.inspect.to_short} to \"/#{meth}\" call.")
        http_resp_obj
    end

    def self.call_oauth_access(code, redirect_uri)
        resp = self.call("oauth.access", {
            "client_id" => SLACK_APP_CLIENT_ID,
            "client_secret" => SLACK_APP_CLIENT_SECRET,
            "code" => code,
            "redirect_uri" => redirect_uri,
        })
        {
            :access_tok => resp["access_token"],
            :scopes => resp["scope"].split(","),
        }
    end

    def self.call_auth_test(access_tok)
        resp = self.call("auth.test", {
            "token" => access_tok,
        })
        {
            :team => resp["team"],
            :team_url => resp["url"],
            :team_id => resp["team_id"],
            :user => resp["user"],
            :user_id => resp["user_id"],
        }
    end

    def self.call_groups_create(access_tok, name)
        resp = self.call("groups.create", {
            "token" => access_tok,
            "name" => name,
        })
        {
            :group_id => resp["group"]["id"],
        }
    end

    def self.call_groups_setpurpose(access_tok, channel_id, purpose)
        self.call("groups.setPurpose", {
            "token" => access_tok,
            "channel" => channel_id,
            "purpose" => purpose,
        })
    end

    def self.call_groups_settopic(access_tok, channel_id, topic)
        self.call("groups.setTopic", {
            "token" => access_tok,
            "channel" => channel_id,
            "topic" => topic,
        })
    end

    def self.call_rtm_start(access_tok)
        resp = self.call("rtm.start", {
            "token" => access_tok,
        })
        {
            :wss_url => resp["url"],
        }
    end

    def self.call_chat_postmessage(access_tok, channel_id, text, as_user = nil)
        data = {
            "token" => access_tok,
            "channel" => channel_id,
            "text" => text,
        }
        unless as_user.nil?
            data.merge!({
                "username" => as_user,
                "icon_url" => "https://textcraft.co/images/puzzle-piece.png",
                "as_user" => false,
            })
        end
        self.call("chat.postMessage", data)
    end

    def self.rtm_send_ping(wss, msg_id)
        wss_msg = { 
            "id" => msg_id,
            "type" => "ping",
        }
        wss.send(wss_msg.to_json)
    end

    def self.rtm_send_msg(wss, msg_id, channel_id, text)
        Console.warn("Message w/ #{msg_id} ID too long, truncating.") if text.length > MAX_RTM_MSG_TEXT_LENGTH
        wss_msg = { 
            "id" => msg_id,
            "type" => "message",
            "channel" => channel_id,
            "text" => text[0...MAX_RTM_MSG_TEXT_LENGTH],
        }
        Console.verbose("About to send #{wss_msg.inspect} low-level message over #{wss} WSS.")
        wss.send(wss_msg.to_json)
    end

end

class WorldConn

    WSS_CONNECT_TIMEOUT = Time::ONE_SECOND * 10
    WSS_PING_FREQ = Time::ONE_SECOND * 5

    IS_NEW_STATUS = "new"
    IS_ACTIVE_STATUS = "active"
    IS_INACTIVE_STATUS = "inactive"
    IS_ARCHIVED_STATUS = "archived"
    IS_REVOKED_STATUS = "revoked"
    IS_TEAM_DISABLED_STATUS = "team_disabled"

    def initialize(init_db, init_slack_access_tok, init_slack_user_id, init_slack_channel_id, init_world_url, init_world_name, init_world_user_name, init_is_init_socket)
        @db = init_db
        @slack_access_tok = init_slack_access_tok
        @slack_user_id = init_slack_user_id
        @slack_channel_id = init_slack_channel_id
        @world_url = init_world_url
        @world_name = init_world_name
        @world_user_name = init_world_user_name
        @is_init_socket = init_is_init_socket
        @socket, @socket_buffer, @socket_last_read_time, @socket_read_th = nil, nil, nil, nil

        @slack_wss_url = SlackApi.call_rtm_start(@slack_access_tok).values_at1(:wss_url)

        @slack_msg_id = 0
        @slack_wss_start_time = Time.now
        Console.debug("Connecting to \"#{@slack_wss_url}\" WSS URL.")
        @slack_wss = WebSocket::EventMachine::Client.connect(:uri => @slack_wss_url)
        open_mutex, open_cv = Mutex.new, ConditionVariable.new
        @slack_wss.onopen do
            Console.verbose("Connection \"onopen\" event from \"#{@slack_wss_url}\" WSS URL.")
            open_mutex.synchronize { open_cv.signal }
        end 
        open_mutex.synchronize { open_cv.wait(open_mutex, WSS_CONNECT_TIMEOUT) }
        Console.debug("Connected to \"#{@slack_wss_url}\" WSS URL.")

        @slack_wss_ping_th = Thread.new do
            loop do
                Console.verbose("Pinging \"#{@slack_wss_url}\" WSS connection.")
                SlackApi.rtm_send_ping(@slack_wss, get_next_slack_msg_id)
                sleep(WSS_PING_FREQ)
            end
        end

        @slack_wss.onmessage do |msg, type|
            msg_obj = JSON.parse(msg)
            Console.verbose("Slack RTM message received: #{msg_obj.inspect} w/ #{type.inspect} type.")
            if (type == :text) && (msg_obj["channel"] == @slack_channel_id) && (msg_obj["user"] == @slack_user_id)
                if Time.at(msg_obj["ts"].to_f) < @slack_wss_start_time
                    Console.verbose("Ignoring stale message #{msg.inspect} from \"#{to_pretty_user}\" user's world connection.")
                else
                    Console.debug("New message #{msg.inspect} from \"#{to_pretty_user}\" user's world connection.")
                    if @socket.nil?
                        Console.info("Initializing socket connection on first new message from \"#{to_pretty_user}\" user's world connection.")
                        initialize_socket
                    end

                    text_slack = msg_obj["text"]
                    text = SlackApi.unformat_slack_msg(text_slack)
                    Console.verbose("Converted \"#{text_slack}\" Slack-formatted text to \"#{text}\" raw socket text.")
                    begin
                        if text =~ %r|^;;|
                            tc_cmd = $'
                            Console.debug("Received \"#{tc_cmd}\" TextCraft command.")
                            case tc_cmd
                            when /^reset$/i
                                Console.debug("Reconnecting \"#{to_pretty_user}\" user's world connection.")
                                initialize_socket
                            when "", /^enter$/i, /^ret(urn)?$/i
                                Console.verbose("Sending newline to \"#{to_pretty_user}\" user's world connection.")
                                write_socket_line("")
                            else
                                write_slack_msg("Unrecognized \"#{tc_cmd}\" TextCraft command.")
                            end
                        else
                            write_socket_line(text)
                        end
                    rescue =>ex
                        Console.warn("Could not send message to \"#{to_pretty_user}\" user's world connection.")
                        initialize_socket
                        write_socket_line(text)  # try once more
                    end
                end
            end
        end 

        @slack_wss.onclose do |code, reason|
            Console.info("Closed \"#{@slack_wss_url}\" w/ \"#{reason}\" (#{code}) reason.")
        end 

        if @is_init_socket
            Console.info("First connection for \"#{@slack_wss_url}\" WSS URL, initializing socket right away.")
            initialize_socket
        end
    end

    def to_pretty_user
        "#@world_user_name (#@world_url)"
    end

    def get_next_slack_msg_id
        @slack_msg_id += 1
        @slack_msg_id
    end

    def write_slack_msg(s)
        as_user = "#@world_name (TextCraft)"
        begin
            SlackApi.call_chat_postmessage(@slack_access_tok, @slack_channel_id, s, as_user)
        rescue ArgumentError =>ex
            if ex.message == "slack_api:is_archived"
                Console.warn("Slack channel for \"#{to_pretty_user}\" user was archived.")
                @db.update_world_connection_status(@slack_channel_id, WorldConn::IS_ARCHIVED_STATUS)
                throw :eof
            elsif ex.message == "slack_api:token_revoked"
                Console.warn("Token revoked for RTM feed on \"#{to_pretty_user}\" user.")
                @db.update_world_connection_status(@slack_channel_id, WorldConn::IS_REVOKED_STATUS)
                throw :eof
            else
                raise
            end
        end
    end
        
    def initialize_socket
        Console.info("Initializing socket connection for \"#{to_pretty_user}\" user.")
        @socket_read_th.kill unless @socket_read_th.nil?
        @socket.close unless @socket.nil?

        world_url_obj = URI(@world_url)
        raise ArgumentError.new("Unrecognized scheme in #{world_url_obj} URL") unless ["telnet", "textcraft"].member?(world_url_obj.scheme)

        Console.debug("Opening socket to \"#{world_url_obj.host}\" host at #{world_url_obj.port} port.")
        @socket = TCPSocket.new(world_url_obj.host, world_url_obj.port)
        @socket_buffer = ''
        world_autologin if world_url_obj.scheme == "textcraft"  # only auto-login if it is our MUD

        @socket_read_th = Thread.new do
            catch :eof do
                loop do
                    resp_lines = read_socket_lines
                    if resp_lines.length > 1
                        resp = SlackApi.format_world_msg(@world_url, resp_lines[0...-1].join("\n"))
                        write_slack_msg(resp) unless resp.nil?
                    end

                    if resp_lines[-1] == :eof
                        break    # from the event loop
                    elsif resp_lines[-1] == :none
                        sleep(0.125)
                    end
                end
            end
            Console.debug("Socket reading thread for \"#{to_pretty_user}\" user finished.")
        end
    end

    def write_socket_line(line)
        Console.verbose("Writing #{line.inspect} line to \"#{to_pretty_user}\" user's socket.")
        @socket.puts line
    end

    def read_socket_line
        Console.verbose("Checking #{@socket_buffer.inspect} socket buffer.")
        if @socket_buffer =~ /\n/
            line = $`
            @socket_buffer = $'
            Console.verbose("Returning #{line.inspect} line.")
            return line
        end

        if (! @socket_buffer.empty?) && ((Time.now - @socket_last_read_time) >= 0.05)
            line_dangling = @socket_buffer
            @socket_buffer = ''
            Console.verbose("Returning #{line_dangling.inspect} dangling line.")
            return line_dangling
        end

        res = @socket.read_nonblock(2**20)  # usually throws a "would block" exception, see below
        Console.verbose("Read #{res.inspect} non-blocking from \"#{to_pretty_user}\" user's socket.")
        @socket_last_read_time = Time.now
        @socket_buffer += res
        return read_socket_line  # try again, with the new input

    rescue Errno::EWOULDBLOCK, Errno::EAGAIN
        Console.verbose("Could not read non-blocking from \"#{to_pretty_user}\" user's socket.")
        return :none
    rescue EOFError, Errno::ECONNRESET
        Console.warn("End-of-file from \"#{to_pretty_user}\" user's socket.")
        return :eof
    end

    def read_socket_lines
        lines = []
        loop do
            lines << read_socket_line
            break if lines[-1].is_a?(Symbol)
        end
        lines
    end

    def read_socket_line_blocking(timeout = 10)
        end_t = Time.now + timeout
        while Time.now < end_t
            line = read_socket_line
            return line unless line.is_a?(Symbol)
            sleep(0.05)
        end
        return :timeout
    end

    def read_socket_until_blocking(re, timeout = 10)
        resp = ''
        Timeout::timeout(timeout) do
            loop do
                resp_line = read_socket_line_blocking
                resp += resp_line + "\n"
                Console.verbose("Read \"#{resp_line}\" response line while blocking until #{re.inspect} match.")
                return resp if resp =~ re
            end
        end
    rescue Timeout::Error
        Console.warn("No match for #{re.inspect} before #{timeout} seconds.")
        :timeout
    end

    def world_autologin
        world_user_password = @world_user_name    # arbitrary convention, security is handled at a higher level
        write_socket_line("create #{@world_user_name} #{world_user_password}")  # always try to create, for simplicity
        write_socket_line("connect #{@world_user_name} #{world_user_password}")
        Console.debug("About to read until connected / created.")
        login_resp = read_socket_until_blocking(/^\*\*\* ((Connected)|(Created)) \*\*\*/, 5)
        if login_resp == :timeout
            Console.warn("Create / connect / password error for \"#{to_pretty_user}\" user.")
            return :err
        end
    end

end

class WorldConns

    NEW_CONN_POLLING_FREQ = Time::ONE_SECOND * 5

    def initialize(init_db)
        @db = init_db
        @conn_map = {}

        @pull_th = Thread.new do
            loop do
                Console.verbose("Polling for new user-to-world connections.")
                @db.each_world_connection_row do |row|
                    next if @conn_map.has_key?(row[:id])
                    Console.info("Found new connection for #{row[:slack_team_name]} (#{row[:slack_team_id]}) team & #{row[:slack_user_name]} (#{row[:slack_user_id]}) user.")

                    is_init_socket = (row[:status] == WorldConn::IS_NEW_STATUS)
                    world_conn = nil
                    begin
                        world_conn = WorldConn.new(@db, row[:slack_access_tok], row[:slack_user_id], row[:slack_channel_id], row[:url], row[:name], row[:world_user_name], is_init_socket)
                        @db.update_world_connection_status(row[:slack_channel_id], WorldConn::IS_ACTIVE_STATUS) if is_init_socket
                    rescue ArgumentError =>ex
                        if ex.message == "slack_api:token_revoked"
                            Console.warn("Token revoked for RTM feed on #{row.inspect} world.")
                            @db.update_world_connection_status(row[:slack_channel_id], WorldConn::IS_REVOKED_STATUS)
                            next
                        elsif ex.message == "slack_api:account_inactive"
                            Console.warn("Account is inactive for RTM feed on #{row.inspect} world.")
                            @db.update_world_connection_status(row[:slack_channel_id], WorldConn::IS_INACTIVE_STATUS)
                            next
                        elsif ex.message == "slack_api:team_disabled"
                            Console.warn("Team has been disabled for RTM feed on #{row.inspect} world.")
                            @db.update_world_connection_status(row[:slack_channel_id], WorldConn::IS_TEAM_DISABLED_STATUS)
                            next
                        else
                            raise
                        end
                    rescue Errno::ECONNREFUSED
                        Console.error("Could not connect to #{row.inspect} world.")
                    end
                    @conn_map[row[:id]] = world_conn
                end
                sleep(NEW_CONN_POLLING_FREQ)
            end
        end
    end

end


class Application <Sinatra::Base

    PWD = File.expand_path(File.dirname(__FILE__))

    set :port, 7443
    set :bind, "0.0.0.0"
    set :show_exceptions, false
    set :raise_errors, false
    set :db, Database.new    # shared across requests
    set :world_conns, WorldConns.new(settings.db)

    helpers Sinatra::Cookies
    use Rack::SSL
    use Rack::Session::Cookie, {
        :expire_after => Time::ONE_WEEK,
        :secret => File.read("#{PWD}/security/cookie_secret").strip,
        :httponly => false,
    }

    def logged_in?
        session.has_key?(:user_id)
    end

    def assert_logged_in!
        raise SecurityError.new("Not logged-in") unless logged_in?
    end

    def assert_slack_callback_user_state_matches!
        exp_user_state = cookies["rack.session"].to_md5
        raise SecurityError.new("slack_api:bad_user_state") unless exp_user_state == params["state"]
    end

    before do
        session[:at] = Time.now    # force session creation
    end

    error do |err|
        err_html = "Error: <code>" + Rack::Utils.escape_html(err.to_s) + "</code>"
        [500, err_html]
    end

    def get_locals
        locals = {
            :slack_app_client_id => SLACK_APP_CLIENT_ID,
        }
        if logged_in?
            user = settings.db.get_user(session[:user_id])
            if user.nil?
                Console.warn("Abandoned #{session[:user_id]} session user ID, logging out.")
                redirect("/logout")
            end

            locals.merge!(user)
            locals[:is_logged_in] = true
            locals[:worlds] = settings.db.get_worlds(user[:id])
        else
            locals[:is_logged_in] = false
            locals[:worlds] = settings.db.get_worlds
        end
        locals
    end

    def get_html_locals
        locals = get_locals
        if session[:flash].nil?
            locals[:flash] = nil
        else
            Console.debug("Setting HTML flash to \"#{session[:flash]}\", and then clearing session.")
            locals[:flash] = session[:flash]
            session.delete(:flash)
        end
        locals
    end

    get("/") do
        redirect("/main")
    end

    get("/main/?") do
        erb(:main, :locals => get_html_locals)
    end

    get("/js/main.js") do
        erb("js/main.js".to_sym, :locals => get_locals, :content_type => "application/javascript")
    end

    get("/logout/?") do
        assert_logged_in!
        session.delete(:user_id)
        redirect("/main")
    end

    def auth_callback
        Console.debug("Doing authentication callback.")
        assert_slack_callback_user_state_matches!

        access_tok, scopes = SlackApi.call_oauth_access(params["code"], request.base_url + request.path_info).values_at1(:access_tok, :scopes)
        Console.debug("Found \"#{access_tok}\" access token & #{scopes.inspect} scopes for user.")

        slack_team, slack_team_id, slack_user, slack_user_id = SlackApi.call_auth_test(access_tok).values_at1(:team, :team_id, :user, :user_id)
        settings.db.auth_slack_user(slack_team, slack_team_id, slack_user, slack_user_id, access_tok, scopes)

        user_id = settings.db.get_user_id_from_slack_ids(slack_team_id, slack_user_id)
        Console.info("User w/ #{user_id} ID just logged-in.")
        session[:user_id] = user_id
    end

    get("/callback/identify/?") do
        Console.debug("Received identify/ callback GET w/ #{params.inspect} parameters.")
        auth_callback

        redirect("/main")
    end

    get("/callback/world-join/:world_id/?") do
        Console.debug("Received world-join/ callback GET w/ #{params.inspect} parameters.")
        auth_callback

        worlds = settings.db.get_worlds(session[:user_id])
        world = worlds.find { |world1| world1[:id] == params[:world_id].to_i }
        raise ArgumentError.new("Already joined world") unless world[:slack_channel_id].nil?

        user = settings.db.get_user(session[:user_id])
        private_group_name = [world[:group_prefix], user[:slack_user_name]].join("-")
        slack_channel_id = SlackApi.call_groups_create(user[:slack_access_tok], private_group_name).values_at1(:group_id)
        channel_desc = "#{user[:slack_user_name]}'s connection to a TextCraft world"
        SlackApi.call_groups_setpurpose(user[:slack_access_tok], slack_channel_id, channel_desc)
        SlackApi.call_groups_settopic(user[:slack_access_tok], slack_channel_id, channel_desc)
        settings.db.join_world(params[:world_id], session[:user_id], slack_channel_id)
        session[:flash] = <<-EOF_HTML

            There is a new private group (i.e. channel) in Slack called
            <span class='tc-world'>#{private_group_name}</span> where you
            can explore the <span class='tc-world'>#{world[:name]}</span>
            world. You&apos;ve joined the game, dive in!

        EOF_HTML

        redirect("/main")
    end

    get('/*') do
        Console.warn("Unrecognized GET w/ #{params.inspect} parameters.")
        404
    end

    post('/*') do
        Console.warn("Unrecognized POST w/ #{params.inspect} parameters.")
        404
    end

    run! do |server|
        begin
            ssl_options = {
                :cert_chain_file => "#{PWD}/security/comodo/textcraft_co.crt",
                :private_key_file => "#{PWD}/security/textcraft_co.key",
                :verify_peer => true,
            }
            server.ssl = true
            server.ssl_options = ssl_options
        rescue IOError =>ex
            Console.error("IOError, \"#{ex}\".")
            raise
        rescue =>ex
            Console.error("Application error, \"#{ex}\".")
            raise
        end
    end

end

