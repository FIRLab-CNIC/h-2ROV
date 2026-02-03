# declare -a command_arr=("./test -a trov -m bash -v v4" "./test -a mrov -m bash -v v4"
#                         "./test -a hbasic -m bash -v v4" "./test -a hbinary -m bash -v v4" "./test -a hnlb -m bash -v v4"
#                         "./test -a trov -m bash -v v6" "./test -a mrov -m bash -v v6"
#                         "./test -a hbasic -m bash -v v6" "./test -a hbinary -m bash -v v6" "./test -a hnlb -m bash -v v6")
declare -a command_arr=("./test")
file_arr=("./result_data/insert.txt" "./result_data/withdrawn.txt" "./result_data/validate.txt")
turn=50
make
for val in "${command_arr[@]}";do
   echo ${val}
   rm result_data/*
   for(( j=1;j<=${turn};j=j+1))
   do
      echo ${j}
      ${val}
   done

   for f in ${file_arr[@]};do
      time=0
      while IFS= read -r line
      do
         time=$(bc -l <<<"${line}+${time}")
      done < "$f"
      echo "scale=3;${time}/${turn}"|bc
   done
   echo "-------------"
done

# BASIC
# .009
# .009
# .472

# BINARY
# .017
# .018
# .413