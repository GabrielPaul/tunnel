#add "set auto-load safe-path current_path" to home directory
define c 
  continue
  refresh
end

define n
  next
  refresh
end

dir /home/gab/zlog/src
b main
run
layout src
