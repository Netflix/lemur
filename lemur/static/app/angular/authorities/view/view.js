'use strict';

angular.module('lemur')

  .config(function config($stateProvider) {
    $stateProvider
      .state('authorities', {
        url: '/authorities',
        templateUrl: '/angular/authorities/view/view.tpl.html',
        controller: 'AuthoritiesViewController'
      })
      .state('authority', {
        url: '/authorities/:name',
        templateUrl: '/angular/authorities/view/view.tpl.html',
        controller: 'AuthoritiesViewController'
      });
  })

  .directive('authorityVisualization', function () {
    // constants
    var margin = {top: 20, right: 120, bottom: 20, left: 120},
    width = 960 - margin.right - margin.left,
    height = 400 - margin.top - margin.bottom;

    return {
      restrict: 'E',
      scope: {
        val: '=',
        grouped: '='
      },
      link: function (scope, element) {
        function update(source) {

          // Compute the new tree layout.
          var nodes = tree.nodes(root).reverse(),
            links = tree.links(nodes);

          // Normalize for fixed-depth.
          nodes.forEach(function(d) { d.y = d.depth * 180; });

          // Update the nodes…
          var node = svg.selectAll('g.node')
            .data(nodes, function(d) { return d.id || (d.id = ++i); });

          // Enter any new nodes at the parent's previous position.
          var nodeEnter = node.enter().append('g')
            .attr('class', 'node')
            .attr('transform', function() { return 'translate(' + source.y0 + ',' + source.x0 + ')'; })
            .on('click', click);

          nodeEnter.append('circle')
            .attr('r', 1e-6)
            .style('fill', function(d) { return d._children ? 'lightsteelblue' : '#fff'; });

          nodeEnter.append('text')
            .attr('x', function(d) { return d.children || d._children ? -10 : 10; })
            .attr('dy', '.35em')
            .attr('text-anchor', function(d) { return d.children || d._children ? 'end' : 'start'; })
            .text(function(d) { return d.name; })
            .style('fill-opacity', 1e-6);

          // Transition nodes to their new position.
          var nodeUpdate = node.transition()
            .duration(duration)
            .attr('transform', function(d) { return 'translate(' + d.y + ',' + d.x + ')'; });

          nodeUpdate.select('circle')
            .attr('r', 4.5)
            .style('fill', function(d) { return d._children ? 'lightsteelblue' : '#fff'; });

          nodeUpdate.select('text')
            .style('fill-opacity', 1);

          // Transition exiting nodes to the parent's new position.
          var nodeExit = node.exit().transition()
            .duration(duration)
            .attr('transform', function() { return 'translate(' + source.y + ',' + source.x + ')'; })
            .remove();

          nodeExit.select('circle')
            .attr('r', 1e-6);

          nodeExit.select('text')
            .style('fill-opacity', 1e-6);

          // Update the links…
          var link = svg.selectAll('path.link')
            .data(links, function(d) { return d.target.id; });

          // Enter any new links at the parent's previous position.
          link.enter().insert('path', 'g')
            .attr('class', 'link')
            .attr('d', function() {
              var o = {x: source.x0, y: source.y0};
              return diagonal({source: o, target: o});
            });

          // Transition links to their new position.
          link.transition()
            .duration(duration)
            .attr('d', diagonal);

          // Transition exiting nodes to the parent's new position.
          link.exit().transition()
            .duration(duration)
            .attr('d', function() {
              var o = {x: source.x, y: source.y};
              return diagonal({source: o, target: o});
            })
            .remove();

          // Stash the old positions for transition.
          nodes.forEach(function(d) {
            d.x0 = d.x;
            d.y0 = d.y;
          });
        }

        // Toggle children on click.
        function click(d) {
          if (d.children) {
            d._children = d.children;
            d.children = null;
          } else {
            d.children = d._children;
            d._children = null;
          }
          update(d);
        }

        var i = 0,
            duration = 750,
            root;

        var tree = d3.layout.tree()
            .size([height, width]);

        var diagonal = d3.svg.diagonal()
            .projection(function(d) { return [d.y, d.x]; });

        var svg = d3.select(element[0]).append('svg')
            .attr('width', width + margin.right + margin.left)
            .attr('height', height + margin.top + margin.bottom)
            .call(d3.behavior.zoom().on('zoom', function () {
              svg.attr('transform', 'translate(' + d3.event.translate + ')' + ' scale(' + d3.event.scale + ')');
            }))
            .append('g')
            .attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

        scope.val.customGET('visualize').then(function (result) {
          root = result;
          root.x0 = height / 2;
          root.y0 = 0;

          function collapse(d) {
            if (d.children) {
              d._children = d.children;
              d._children.forEach(collapse);
              d.children = null;
            }
          }

          root.children.forEach(collapse);
          update(root);

        });

        d3.select(self.frameElement).style('height', '800px');

      }
    };
  })

  .controller('AuthoritiesViewController', function ($scope, $q, $uibModal, $stateParams, AuthorityApi, AuthorityService, MomentService, ngTableParams, toaster) {
    $scope.filter = $stateParams;
    $scope.authoritiesTable = new ngTableParams({
      page: 1,            // show first page
      count: 10,          // count per page
      sorting: {
        id: 'desc'     // initial sorting
      },
      filter: $scope.filter
    }, {
      total: 0,           // length of data
      getData: function ($defer, params) {
        AuthorityApi.getList(params.url()).then(function (data) {
          params.total(data.total);
          $defer.resolve(data);
        });
      }
    });

    $scope.momentService = MomentService;

    $scope.updateActive = function (authority) {
      AuthorityService.updateActive(authority).then(
				function () {
					toaster.pop({
						type: 'success',
						title: authority.name,
						body: 'Successfully updated!'
					});
				},
				function (response) {
					toaster.pop({
						type: 'error',
						title: authority.name,
						body: 'Update Failed! ' + response.data.message,
            timeout: 100000
					});
				});
    };

    $scope.getAuthorityStatus = function () {
      var def = $q.defer();
      def.resolve([{'title': 'Active', 'id': true}, {'title': 'Inactive', 'id': false}]);
      return def;
    };

    $scope.edit = function (authorityId) {
      var uibModalInstance = $uibModal.open({
        animation: true,
        templateUrl: '/angular/authorities/authority/edit.tpl.html',
        controller: 'AuthorityEditController',
        size: 'lg',
        backdrop: 'static',
        resolve: {
          editId: function () {
            return authorityId;
          }
        }
      });

      uibModalInstance.result.then(function () {
        $scope.authoritiesTable.reload();
      });

    };

    $scope.editRole = function (roleId) {
      var uibModalInstance = $uibModal.open({
        animation: true,
        templateUrl: '/angular/roles/role/role.tpl.html',
        controller: 'RolesEditController',
        size: 'lg',
        backdrop: 'static',
        resolve: {
          editId: function () {
            return roleId;
          }
        }
      });

      uibModalInstance.result.then(function () {
        $scope.authoritiesTable.reload();
      });

    };

    $scope.create = function () {
      var uibModalInstance = $uibModal.open({
        animation: true,
        controller: 'AuthorityCreateController',
        templateUrl: '/angular/authorities/authority/authorityWizard.tpl.html',
        size: 'lg',
        backdrop: 'static',
      });

      uibModalInstance.result.then(function () {
        $scope.authoritiesTable.reload();
      });

    };
  });
