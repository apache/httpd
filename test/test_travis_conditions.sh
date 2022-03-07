#!/bin/sh -e
# Script to test whether travis conditions match correctly.
# "gem install travis-conditions". Tests .travis.yml in the cwd.

cond_24x="`sed -n '/&condition_24x_only/{s/.*condition_24x_only//;p;q;}' .travis.yml`"
cond_not_24x="`sed -n '/&condition_not_24x/{s/.*condition_not_24x//;p;q;}' .travis.yml`"

echo Condition 2.4.x: ${cond_24x}
echo Condition not 2.4.x: ${cond_not_24x}

function testit()
{
    local data=$1
    local expect=$2

    is_24x=`travis-conditions eval "$cond_24x" --data "${data}"`
    not_24x=`travis-conditions eval "$cond_not_24x" --data "${data}"`

    if [ $is_24x = $not_24x ]; then
        echo FAIL: Tests as both 2.4.x and not 2.4.x for "$data"
        return 1
    elif [ $expect = 2.4.x -a $is_24x = true ]; then
        echo PASS
    elif [ $expect = trunk ]; then
        echo PASS
    else
        echo FAIL for "$data"
        return 1
    fi
    return 0
}

testit '{"tag": "2.4.49"}' 2.4.x
testit '{"tag": "2.5.59"}' trunk
testit '{"branch": "2.4.x"}' 2.4.x
testit '{"branch": "candidate-2.4.49"}' 2.4.x
testit '{"branch": "2.4.55-candidate"}' 2.4.x
testit '{"branch": "2.4-backport-branch"}' 2.4.x
testit '{"branch": "2.4.x-something"}' 2.4.x
testit '{"branch": "2.5.0"}' trunk
testit '{"branch": "2.5.x"}' trunk
testit '{"branch": "trunk"}' trunk
